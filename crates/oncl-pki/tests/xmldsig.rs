//! XML canonicalization (W3C vectors), XMLDSig signing in the Kalkan shape (enveloped and
//! element), verification of our signatures and of documents signed by Kalkan (NCANode test
//! resources), tampering, and hostile input.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_pki::cert;
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::xmldsig::{
    C14n, MAX_INPUT, MAX_NODES, NodeRef, XmlError, canonicalize, sign_element, sign_enveloped,
    verify,
};
use oncl_testkit::{ncanode, read, synthetic};
use std::time::{Duration, Instant};

const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

/// The synthetic signing keys with the algorithm each certificate calls for.
fn signers() -> [(KeyEntry, SigAlg); 3] {
    [
        (entry("user-gost2015-sign"), SigAlg::Gost2015_512),
        (entry("user-gost2004-sign"), SigAlg::Gost2004),
        (entry("user-rsa-sign"), SigAlg::RsaSha256),
    ]
}

fn c14n(xml: &str, method: C14n) -> String {
    String::from_utf8(canonicalize(xml.as_bytes(), method, None).unwrap()).unwrap()
}

fn enveloped(xml: &[u8], signer: &KeyEntry) -> Vec<u8> {
    sign_enveloped(xml, &signer.key, &signer.cert).unwrap()
}

fn find(haystack: &[u8], needle: &str) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap_or_else(|| panic!("{needle:?} not found"))
}

fn rfind(haystack: &[u8], needle: &str) -> usize {
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle.as_bytes())
        .unwrap_or_else(|| panic!("{needle:?} not found"))
}

fn replace_once(xml: &[u8], from: &str, to: &str) -> Vec<u8> {
    let at = find(xml, from);
    [&xml[..at], to.as_bytes(), &xml[at + from.len()..]].concat()
}

fn algs(infos: &[oncl_pki::xmldsig::XmlSignatureInfo]) -> Vec<SigAlg> {
    infos.iter().map(|i| i.sig_alg).collect()
}

// --- Canonical XML 1.0, section 3 examples (DTD-dependent parts left out) ---

const C14N_3_1: &str = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n";

#[test]
fn c14n_3_1_pis_comments_and_outside_of_document_element() {
    // The example's `<!DOCTYPE doc SYSTEM "doc.dtd">` is left out: DOCTYPE is refused.
    assert_eq!(
        c14n(C14N_3_1, C14n::Inclusive),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
    );
    assert_eq!(
        c14n(C14N_3_1, C14n::InclusiveWithComments),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
    );
}

#[test]
fn c14n_3_2_whitespace_in_document_content() {
    let xml = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
    assert_eq!(c14n(xml, C14n::Inclusive), xml);
}

#[test]
fn c14n_3_3_start_and_end_tags() {
    // Without the DTD, e9's defaulted attribute is written out in the input.
    let xml = "<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\" attr=\"default\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>";
    let expected = "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\" attr=\"default\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>";
    assert_eq!(c14n(xml, C14n::Inclusive), expected);
}

#[test]
fn c14n_3_4_character_modifications_and_references() {
    // The ID and NMTOKENS attributes need the DTD and are left out.
    let xml = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";
    let expected = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";
    assert_eq!(c14n(xml, C14n::Inclusive), expected);
}

#[test]
fn c14n_3_6_utf8_encoding() {
    let xml = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>&#169;</doc>";
    assert_eq!(
        canonicalize(xml.as_bytes(), C14n::Inclusive, None).unwrap(),
        b"<doc>\xC2\xA9</doc>"
    );
}

#[test]
fn c14n_line_ends_and_bom() {
    let xml =
        "\u{FEFF}<?xml version=\"1.0\"?>\r\n<!--a\r\nb-->\r\n<doc a=\"x\r\ny\">1\r\n2\r3</doc>";
    // CRLF is a line feed first, then a space in the attribute value.
    assert_eq!(
        c14n(xml, C14n::InclusiveWithComments),
        "<!--a\nb-->\n<doc a=\"x y\">1\n2\n3</doc>"
    );
}

#[test]
fn exclusive_c14n_of_a_document() {
    // Section 2.2 of Exclusive XML Canonicalization: unused namespace declarations vanish,
    // used ones move to the element using them; xml:* attributes stay where they are.
    let xml = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n2:pdu>";
    assert_eq!(
        c14n(xml, C14n::Exclusive),
        "<n2:pdu xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff></n1:elem2></n2:pdu>"
    );
    assert_eq!(
        c14n(xml, C14n::Inclusive),
        "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff></n1:elem2></n2:pdu>"
    );
    let commented = "<a:r xmlns:a=\"urn:a\" xmlns:b=\"urn:b\"><!--x--><b:e/></a:r>";
    assert_eq!(
        c14n(commented, C14n::ExclusiveWithComments),
        "<a:r xmlns:a=\"urn:a\"><!--x--><b:e xmlns:b=\"urn:b\"></b:e></a:r>"
    );
    assert_eq!(
        c14n(commented, C14n::Exclusive),
        "<a:r xmlns:a=\"urn:a\"><b:e xmlns:b=\"urn:b\"></b:e></a:r>"
    );
}

#[test]
fn c14n_excludes_a_subtree() {
    let xml = format!("<r>\n<a/><ds:Signature xmlns:ds=\"{DSIG}\"><x/></ds:Signature>\n<b/></r>");
    let at = xml.find("<ds:Signature").unwrap();
    let out = canonicalize(
        xml.as_bytes(),
        C14n::Inclusive,
        Some(NodeRef::element_at(at)),
    )
    .unwrap();
    assert_eq!(out, b"<r>\n<a></a>\n<b></b></r>");
    assert!(matches!(
        canonicalize(
            xml.as_bytes(),
            C14n::Inclusive,
            Some(NodeRef::element_at(at + 1))
        ),
        Err(XmlError::Parse(_))
    ));
}

#[test]
fn c14n_method_uris() {
    for method in [
        C14n::Inclusive,
        C14n::InclusiveWithComments,
        C14n::Exclusive,
        C14n::ExclusiveWithComments,
    ] {
        assert_eq!(C14n::from_uri(method.uri()), Some(method));
    }
    assert_eq!(C14n::from_uri("http://www.w3.org/2006/12/xml-c14n11"), None);
}

// --- Enveloped signing ---

/// Declaration, BOM, comments, CRLF, a default namespace and attributes out of order.
const AWKWARD: &str = "\u{FEFF}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<!-- head -->\r\n<doc xmlns=\"urn:example:doc\" z=\"1\" a=\"2\" xmlns:p=\"urn:p\" xml:lang=\"ru\">\r\n  <p:item b=\"x\" a=\"y\">Мәтін &amp; text<!-- inner --></p:item>\r\n  <empty/>\r\n</doc>\r\n<!-- tail -->\r\n";

#[test]
fn enveloped_signature_verifies_and_keeps_the_document_bytes() {
    for (signer, alg) in signers() {
        let signed = enveloped(AWKWARD.as_bytes(), &signer);
        let start = find(&signed, "<ds:Signature");
        let end = find(&signed, "</ds:Signature>") + "</ds:Signature>".len();
        let insert_at = AWKWARD.find("</doc>").unwrap();
        assert_eq!(start, insert_at, "{alg:?}");
        assert_eq!(&signed[..start], &AWKWARD.as_bytes()[..insert_at]);
        assert_eq!(&signed[end..], &AWKWARD.as_bytes()[insert_at..]);

        let infos = verify(&signed).unwrap();
        assert_eq!(algs(&infos), [alg]);
        assert_eq!(infos[0].cert, signer.cert);
    }
}

#[test]
fn enveloped_signature_has_the_kalkan_shape() {
    let uris = [
        (
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
    ];
    for ((signer, alg), (signature_method, digest_method)) in signers().into_iter().zip(uris) {
        let signed = enveloped(b"<a><b>test</b></a>", &signer);
        let signed = std::str::from_utf8(&signed).unwrap();
        let expected_head = format!(
            "<a><b>test</b><ds:Signature xmlns:ds=\"{DSIG}\">\n<ds:SignedInfo>\n\
             <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n\
             <ds:SignatureMethod Algorithm=\"{signature_method}\"/>\n\
             <ds:Reference URI=\"\">\n<ds:Transforms>\n\
             <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n\
             <ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/>\n\
             </ds:Transforms>\n<ds:DigestMethod Algorithm=\"{digest_method}\"/>\n<ds:DigestValue>"
        );
        assert!(signed.starts_with(&expected_head), "{alg:?}: {signed}");
        assert!(signed.ends_with(
            "</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature></a>"
        ));
        assert!(!signed.contains("Id="), "{alg:?}");
        assert!(!signed.contains("Object"), "{alg:?}");

        let cert_start = signed.find("<ds:X509Certificate>\n").unwrap() + 21;
        let cert_end = signed.find("\n</ds:X509Certificate>").unwrap();
        let cert_b64 = &signed[cert_start..cert_end];
        assert!(cert_b64.split("&#13;\n").all(|line| line.len() <= 76));
        assert_eq!(
            STANDARD.decode(cert_b64.replace("&#13;\n", "")).unwrap(),
            signer.cert.to_der().unwrap()
        );
        assert!(signed.contains("<ds:SignatureValue>\n"));
    }
}

#[test]
fn signatures_cascade() {
    let [gost2015, gost2004, rsa] = signers();
    let once = enveloped(AWKWARD.as_bytes(), &gost2015.0);
    let twice = enveloped(&once, &rsa.0);
    let thrice = enveloped(&twice, &gost2004.0);
    assert_eq!(
        algs(&verify(&twice).unwrap()),
        [SigAlg::RsaSha256, SigAlg::Gost2015_512]
    );
    let infos = verify(&thrice).unwrap();
    assert_eq!(
        algs(&infos),
        [SigAlg::Gost2004, SigAlg::RsaSha256, SigAlg::Gost2015_512]
    );
    assert_eq!(infos[2].cert, gost2015.0.cert);
    // Each signature only appends.
    assert!(thrice.starts_with(&twice[..find(&twice, "</doc>")]));
}

#[test]
fn tampering_is_detected() {
    let [(signer, _), ..] = signers();
    let signed = enveloped(AWKWARD.as_bytes(), &signer);

    let content = replace_once(&signed, "Мәтін", "Мәтiн");
    assert_eq!(verify(&content), Err(XmlError::BadDigest));
    let attribute = replace_once(&signed, "a=\"y\"", "a=\"z\"");
    assert_eq!(verify(&attribute), Err(XmlError::BadDigest));

    let at = find(&signed, "<ds:SignatureValue>\n") + "<ds:SignatureValue>\n".len();
    let mut value = signed.clone();
    value[at] = if value[at] == b'A' { b'B' } else { b'A' };
    assert_eq!(verify(&value), Err(XmlError::BadSignature));

    // A comment is not signed: same-document references drop comments.
    let comment = replace_once(&signed, "<!-- inner -->", "<!-- changed -->");
    assert!(verify(&comment).is_ok());
}

#[test]
fn sha1_rsa_certificates_are_refused() {
    let [_, _, (signer, _)] = signers();
    let sha256_rsa = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    let mut der = signer.cert.to_der().unwrap();
    let mut patched = 0;
    for at in 0..der.len() - sha256_rsa.len() {
        if der[at..].starts_with(&sha256_rsa) {
            der[at + sha256_rsa.len() - 1] = 0x05;
            patched += 1;
        }
    }
    assert_eq!(patched, 2);
    let sha1_cert = cert::parse(&der).unwrap();
    assert_eq!(
        sign_enveloped(b"<a/>", &signer.key, &sha1_cert),
        Err(XmlError::UnsupportedAlgorithm(
            "1.2.840.113549.1.1.5".to_owned()
        ))
    );
    // Kalkan parses the document first and checks the algorithm before any XPath.
    assert!(matches!(
        sign_enveloped(b"<a>", &signer.key, &sha1_cert),
        Err(XmlError::Parse(_))
    ));
    assert!(matches!(
        sign_element(b"<a>", "//b", None, &signer.key, &sha1_cert),
        Err(XmlError::Parse(_))
    ));
    assert!(matches!(
        sign_element(b"<a/>", "//b", None, &signer.key, &sha1_cert),
        Err(XmlError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn key_must_fit_the_certificate_algorithm() {
    let [(gost2015, _), _, (rsa, _)] = signers();
    assert!(matches!(
        sign_enveloped(b"<a/>", &gost2015.key, &rsa.cert),
        Err(XmlError::Key(_))
    ));
}

#[test]
fn empty_document_element_is_opened() {
    let [(signer, _), ..] = signers();
    let signed = enveloped(
        b"<?xml version=\"1.0\"?>\n<p:doc xmlns:p=\"urn:p\" />",
        &signer,
    );
    assert!(
        signed.starts_with(b"<?xml version=\"1.0\"?>\n<p:doc xmlns:p=\"urn:p\" ><ds:Signature")
    );
    assert!(signed.ends_with(b"</ds:Signature></p:doc>"));
    verify(&signed).unwrap();
}

#[test]
fn unsigned_document_has_no_signature() {
    assert_eq!(verify(b"<a><b/></a>"), Err(XmlError::NoSignature));
}

// --- Element signing ---

const ELEMENTS: &str = "<root xmlns:x=\"urn:x\">\n  <head Id=\"h\"/>\n  <body Id=\"b1\"><data Id=\"d1\" x:k=\"v\">one</data></body>\n  <body Id=\"b2\">two<!-- c --></body>\n  <plain/>\n</root>";

#[test]
fn element_signatures_verify() {
    for (signer, alg) in signers() {
        for (xpath, id) in [("//data", "d1"), ("/root/body[2]", "b2")] {
            let signed =
                sign_element(ELEMENTS.as_bytes(), xpath, None, &signer.key, &signer.cert).unwrap();
            let text = std::str::from_utf8(&signed).unwrap();
            assert!(text.contains(&format!("<ds:Reference URI=\"#{id}\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/>\n</ds:Transforms>")));
            assert!(text.contains(
                "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            ));
            let at = ELEMENTS.find("</root>").unwrap();
            assert_eq!(&signed[..at], &ELEMENTS.as_bytes()[..at]);
            assert!(text.ends_with("</ds:Signature></root>"));
            assert_eq!(algs(&verify(&signed).unwrap()), [alg], "{xpath}");

            let tampered =
                replace_once(&signed, if id == "d1" { ">one<" } else { ">two<" }, ">six<");
            assert_eq!(verify(&tampered), Err(XmlError::BadDigest));
            // Outside the signed element nothing is covered.
            assert!(verify(&replace_once(&signed, "<plain/>", "<plain a=\"1\"/>")).is_ok());
        }
    }
}

#[test]
fn element_signature_goes_into_the_parent() {
    let [(signer, _), _, (rsa, _)] = signers();
    let signed = sign_element(
        ELEMENTS.as_bytes(),
        "//data",
        Some("/root/head"),
        &signer.key,
        &signer.cert,
    )
    .unwrap();
    assert!(find(&signed, "<head Id=\"h\"><ds:Signature") > 0);
    assert_eq!(algs(&verify(&signed).unwrap()), [SigAlg::Gost2015_512]);

    let both = sign_element(
        &signed,
        "/root/body[2]",
        Some("//plain"),
        &rsa.key,
        &rsa.cert,
    )
    .unwrap();
    assert!(rfind(&both, "<plain><ds:Signature") > find(&both, "<head Id=\"h\"><ds:Signature"));
    assert_eq!(
        algs(&verify(&both).unwrap()),
        [SigAlg::RsaSha256, SigAlg::Gost2015_512]
    );
}

#[test]
fn element_signatures_on_different_elements_both_verify() {
    let [(gost, _), _, (rsa, _)] = signers();
    // Inner element signed first, its signature placed in the body; then the body (with the
    // inner signature inside) signed, its signature placed in the head: the usual SOAP
    // layout. The inner signature is not a child of the root, so it stays covered.
    let xml = b"<root><head/><body Id=\"b\"><inner Id=\"i\">x</inner></body></root>";
    let inner = sign_element(xml, "//inner", Some("/root/body"), &gost.key, &gost.cert).unwrap();
    assert_eq!(algs(&verify(&inner).unwrap()), [SigAlg::Gost2015_512]);
    let outer = sign_element(
        &inner,
        "/root/body",
        Some("/root/head"),
        &rsa.key,
        &rsa.cert,
    )
    .unwrap();
    assert_eq!(
        algs(&verify(&outer).unwrap()),
        [SigAlg::Gost2015_512, SigAlg::RsaSha256]
    );

    // Two element signatures appended to the root.
    let first = sign_element(ELEMENTS.as_bytes(), "//data", None, &gost.key, &gost.cert).unwrap();
    let second = sign_element(&first, "/root/body[2]", None, &rsa.key, &rsa.cert).unwrap();
    assert_eq!(
        algs(&verify(&second).unwrap()),
        [SigAlg::RsaSha256, SigAlg::Gost2015_512]
    );
}

#[test]
fn signature_inserted_into_a_signed_element_breaks_it() {
    let [(gost, _), _, (rsa, _)] = signers();
    let first = sign_element(ELEMENTS.as_bytes(), "//data", None, &gost.key, &gost.cert).unwrap();
    // The second signature lands inside the element the first one covers.
    let second =
        sign_element(&first, "/root/body[2]", Some("//data"), &rsa.key, &rsa.cert).unwrap();
    assert!(find(&second, "x:k=\"v\">one<ds:Signature") > 0);
    assert_eq!(verify(&second), Err(XmlError::BadDigest));
}

#[test]
fn id_with_line_break_character_references_round_trips() {
    let [(signer, _), ..] = signers();
    let xml = b"<root><data Id=\"a&#10;b&#9;c&#13;\">x</data></root>";
    let signed = sign_element(xml, "//data", None, &signer.key, &signer.cert).unwrap();
    assert!(find(&signed, "<ds:Reference URI=\"#a&#xA;b&#x9;c&#xD;\">") > 0);
    assert_eq!(algs(&verify(&signed).unwrap()), [SigAlg::Gost2015_512]);
}

#[test]
fn element_signing_constraints() {
    let [(signer, _), ..] = signers();
    let sign = |tbs: &str, parent: Option<&str>| {
        sign_element(ELEMENTS.as_bytes(), tbs, parent, &signer.key, &signer.cert)
    };
    // Kalkan refuses an element without `Id` rather than adding one.
    assert!(matches!(
        sign("/root/plain", None),
        Err(XmlError::Constraint(_))
    ));
    assert!(matches!(
        sign("//missing", None),
        Err(XmlError::Constraint(_))
    ));
    assert!(matches!(
        sign("//data", Some("//missing")),
        Err(XmlError::Constraint(_))
    ));
    assert!(matches!(
        sign("/root/body[1]", Some("/root/body[1]")),
        Err(XmlError::Constraint(_))
    ));
    assert!(matches!(
        sign("/root/body[1]", Some("//data")),
        Err(XmlError::Constraint(_))
    ));
    for bad in ["/root/body[@Id='b1']", "root/body", "/root/*", ""] {
        assert!(
            matches!(sign(bad, None), Err(XmlError::XPath(_))),
            "{bad:?}"
        );
    }
    assert!(matches!(sign("//data", Some("")), Err(XmlError::XPath(_))));

    let twice = ELEMENTS.replace("<plain/>", "<plain id=\"d1\"/>");
    assert!(matches!(
        sign_element(twice.as_bytes(), "//data", None, &signer.key, &signer.cert),
        Err(XmlError::Constraint(_))
    ));
    // The document element with an Id cannot hold its own signature.
    assert!(matches!(
        sign_element(b"<r Id=\"r\"/>", "/r", None, &signer.key, &signer.cert),
        Err(XmlError::Constraint(_))
    ));
}

// --- Documents signed by Kalkan (NCANode test resources) ---

#[test]
fn kalkan_enveloped_documents_verify() {
    let one = read(ncanode("xmldsig-signed-rsa.xml"));
    let infos = verify(&one).unwrap();
    assert_eq!(algs(&infos), [SigAlg::RsaSha256]);

    let two = read(ncanode("xmldsig-signed-rsa-gost2015.xml"));
    assert_eq!(
        algs(&verify(&two).unwrap()),
        [SigAlg::Gost2015_512, SigAlg::RsaSha256]
    );
    assert_eq!(
        verify(&replace_once(&two, "<b>test</b>", "<b>Test</b>")),
        Err(XmlError::BadDigest)
    );

    // Our signature appended to Kalkan's.
    let [(signer, _), ..] = signers();
    let three = enveloped(&two, &signer);
    assert_eq!(
        algs(&verify(&three).unwrap()),
        [
            SigAlg::Gost2015_512,
            SigAlg::Gost2015_512,
            SigAlg::RsaSha256
        ]
    );
}

#[test]
fn ncanode_xades_documents_verify() {
    for level in ["b", "t", "lt", "lta"] {
        let xml = read(ncanode(&format!("xades-test-signed-{level}.xml")));
        let infos = verify(&xml).unwrap();
        assert_eq!(algs(&infos), [SigAlg::Gost2015_512], "{level}");

        let content = replace_once(&xml, "conformance test", "conformance tesT");
        assert_eq!(verify(&content), Err(XmlError::BadDigest), "{level}");
        let signed_properties =
            replace_once(&xml, "<xades:MimeType>text/xml", "<xades:MimeType>text/XML");
        assert_eq!(
            verify(&signed_properties),
            Err(XmlError::BadDigest),
            "{level}"
        );
    }
}

// --- Hostile input ---

#[test]
fn doctype_is_refused() {
    let [(signer, _), ..] = signers();
    let billion_laughs = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><lolz>&lol3;</lolz>";
    let external = "<!DOCTYPE a [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><a>&x;</a>";
    let plain = "<!-- c --><!DOCTYPE a SYSTEM \"a.dtd\"><a/>";
    for xml in [billion_laughs, external, plain, "<!DOCTYPE a><a/>"] {
        let xml = xml.as_bytes();
        assert_eq!(
            canonicalize(xml, C14n::Inclusive, None),
            Err(XmlError::Doctype)
        );
        assert_eq!(verify(xml), Err(XmlError::Doctype));
        assert_eq!(
            sign_enveloped(xml, &signer.key, &signer.cert),
            Err(XmlError::Doctype)
        );
    }
    // Only the predefined entities exist.
    assert!(matches!(verify(b"<a>&x;</a>"), Err(XmlError::Parse(_))));
}

#[test]
fn deep_nesting_is_refused_quickly() {
    let [(signer, _), ..] = signers();
    let deep = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));
    let started = Instant::now();
    assert_eq!(verify(deep.as_bytes()), Err(XmlError::TooDeep));
    assert_eq!(
        sign_enveloped(deep.as_bytes(), &signer.key, &signer.cert),
        Err(XmlError::TooDeep)
    );
    assert_eq!(
        canonicalize(deep.as_bytes(), C14n::Inclusive, None),
        Err(XmlError::TooDeep)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );

    let nested = |levels: usize| {
        format!(
            "{}<b x='>'/>{}",
            "<a>".repeat(levels - 1),
            "</a>".repeat(levels - 1)
        )
    };
    assert!(verify(nested(256).as_bytes()) == Err(XmlError::NoSignature));
    assert_eq!(verify(nested(257).as_bytes()), Err(XmlError::TooDeep));
}

#[test]
fn oversized_input_is_refused() {
    let [(signer, _), ..] = signers();
    let mut big = vec![b' '; 65 * 1024 * 1024];
    big[..3].copy_from_slice(b"<a>");
    assert!(big.len() > MAX_INPUT);
    assert_eq!(verify(&big), Err(XmlError::TooLarge));
    assert_eq!(
        sign_enveloped(&big, &signer.key, &signer.cert),
        Err(XmlError::TooLarge)
    );
    assert_eq!(
        canonicalize(&big, C14n::Inclusive, None),
        Err(XmlError::TooLarge)
    );
}

/// `<r>` declaring `declarations` namespaces, with `children` empty `<c/>` children.
fn namespace_heavy(declarations: usize, children: usize) -> String {
    let declarations: String = (0..declarations)
        .map(|i| format!(" xmlns:n{i}='u{i}'"))
        .collect();
    format!("<r{declarations}>{}</r>", "<c/>".repeat(children))
}

#[test]
fn namespace_floods_are_refused_quickly() {
    // The parser resolves every element name among the namespaces in scope. At full scale,
    // 8 192 declarations on the root and 16.7 M children fill 64 MiB; here a sixteenth of
    // that is refused before any tree is built, by all three entry points. `TooLarge` is
    // the functional check. The time bound only catches a superlinear refusal (about
    // 8.6·10⁹ name lookups, many seconds even optimized) and leaves a loaded debug CI runner,
    // where the linear pre-scan takes well under a second, ample headroom.
    let [(signer, _), ..] = signers();
    let xml = namespace_heavy(8_192, 16_736_000 / 16);
    let started = Instant::now();
    assert_eq!(verify(xml.as_bytes()), Err(XmlError::TooLarge));
    assert_eq!(
        sign_enveloped(xml.as_bytes(), &signer.key, &signer.cert),
        Err(XmlError::TooLarge)
    );
    assert_eq!(
        canonicalize(xml.as_bytes(), C14n::Inclusive, None),
        Err(XmlError::TooLarge)
    );
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn many_namespaces_in_scope_still_sign_and_verify() {
    // 8 192 namespaces on the root are rendered once, not looked at for each element.
    let [(signer, _), ..] = signers();
    let xml = namespace_heavy(8_192, 20_000);
    let started = Instant::now();
    let canonical = canonicalize(xml.as_bytes(), C14n::Inclusive, None).unwrap();
    assert!(canonical.ends_with(b"<c></c></r>"));
    let exclusive = canonicalize(xml.as_bytes(), C14n::Exclusive, None).unwrap();
    assert!(exclusive.starts_with(b"<r><c></c>"));
    let signed = enveloped(xml.as_bytes(), &signer);
    assert_eq!(algs(&verify(&signed).unwrap()), [SigAlg::Gost2015_512]);
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn reference_work_is_bounded() {
    // Each reference may canonicalize the whole document: 17 references over a 64 MiB
    // document are refused before any work, 16 are processed (and fail as malformed here).
    let document = |references: usize| {
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{DSIG}\"><ds:SignedInfo>{}</ds:SignedInfo></ds:Signature>",
            "<ds:Reference URI=\"\"/>".repeat(references)
        );
        let padding = MAX_INPUT - signature.len() - "<r><p></p></r>".len();
        format!("<r><p>{}</p>{signature}</r>", "x".repeat(padding))
    };
    assert_eq!(verify(document(17).as_bytes()), Err(XmlError::TooLarge));
    assert!(matches!(
        verify(document(16).as_bytes()),
        Err(XmlError::Parse(_))
    ));
}

#[test]
fn malformed_and_non_utf8_input_is_refused() {
    for xml in [
        &b"<a><b></a>"[..],
        b"",
        b"text",
        b"<a/><b/>",
        b"<a>\xFF</a>",
        b"<p:a/>",
    ] {
        assert!(matches!(verify(xml), Err(XmlError::Parse(_))), "{xml:?}");
    }
}

#[test]
fn element_floods_are_refused_quickly() {
    // 13 million elements in 50 MiB: more `<` than MAX_NODES, refused before any tree is
    // built (whose node array alone would take about a gigabyte). The bound is generous for
    // a loaded debug runner; `TooLarge` is the functional check.
    let xml = format!("<r>{}</r>", "<a/>".repeat(50 * 1024 * 1024 / 4));
    let started = Instant::now();
    assert_eq!(verify(xml.as_bytes()), Err(XmlError::TooLarge));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");

    // At the node cap, 50 MiB still gets an answer.
    let element = format!("<a>{}</a>", "x".repeat(50 * 1024 * 1024 / (MAX_NODES / 2)));
    let xml = format!("<r>{}</r>", element.repeat(MAX_NODES / 2 - 2));
    assert_eq!(verify(xml.as_bytes()), Err(XmlError::NoSignature));
}
