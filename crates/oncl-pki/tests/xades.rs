//! XAdES-BASELINE-B, -T and -LT signatures ([`oncl_pki::xades::sign`]): the signed
//! properties under their own reference, the signature time-stamp over the canonical
//! `SignatureValue`, the chain and OCSP responses, each signature verified.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_pki::cert::{self, Certificate};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport, RouteTransport};
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::{self, MockTsa, TsaProfile, TsaSpec};
use oncl_pki::xades::{XadesError, XadesLevel, XadesSpec, sign};
use oncl_pki::xmldsig::{XmlError, verify};
use oncl_testkit::{read, synthetic, synthetic_cert};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::macros::datetime;

const DOC: &[u8] = b"<?xml version=\"1.0\"?>\n<doc xmlns=\"urn:x\"><a>1</a></doc>";
const NOW: OffsetDateTime = datetime!(2026-10-29 12:00 UTC);
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const OCSP_URL: &str = "http://ocsp.synthetic.test";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

/// A transport without network.
struct Offline;

impl HttpTransport for Offline {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other(format!("offline: {}", request.url)))
    }
}

fn tsa_spec() -> TsaSpec {
    TsaSpec::from(TsaProfile::basics_default())
}

fn spec(level: XadesLevel, chain: Vec<Certificate>) -> XadesSpec<'static> {
    XadesSpec {
        level,
        tsa: (level != XadesLevel::B).then(tsa_spec),
        chain,
        signature_method: None,
        digest_method: None,
    }
}

/// The mock TSA and OCSP responder of the synthetic PKI.
fn pki(ocsp: bool) -> RouteTransport {
    let mut routes: Vec<(String, Arc<dyn HttpTransport>)> = vec![(
        tsa_spec().url,
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
    )];
    if ocsp {
        routes.push((
            OCSP_URL.to_owned(),
            Arc::new(MockOcsp::new(entry("ocsp-gost2015"))),
        ));
    }
    RouteTransport::new(routes)
}

fn text(xml: &[u8]) -> &str {
    std::str::from_utf8(xml).unwrap()
}

/// The text of the first element `name` (as written, with its prefix) in `xml`.
fn element_text<'a>(xml: &'a str, name: &str) -> &'a str {
    let start = xml
        .find(&format!("<{name}"))
        .unwrap_or_else(|| panic!("no {name}"));
    let open_end = start + xml[start..].find('>').unwrap() + 1;
    let close = open_end + xml[open_end..].find(&format!("</{name}>")).unwrap();
    &xml[open_end..close]
}

/// The base64 of every element `name` in `xml`, decoded.
fn all_base64(xml: &str, name: &str) -> Vec<Vec<u8>> {
    xml.match_indices(&format!("<{name}>"))
        .map(|(at, open)| {
            let from = at + open.len();
            let to = from + xml[from..].find(&format!("</{name}>")).unwrap();
            STANDARD.decode(&xml[from..to]).unwrap()
        })
        .collect()
}

#[test]
fn xades_b_structure() {
    let signer = entry("user-gost2015-sign");
    let signed = sign(
        DOC,
        &spec(XadesLevel::B, Vec::new()),
        &signer.key,
        &signer.cert,
        &Offline,
        NOW,
    )
    .unwrap();
    let xml = text(&signed);
    assert!(xml.starts_with("<?xml version=\"1.0\"?>\n<doc xmlns=\"urn:x\"><a>1</a><ds:Signature"));
    let sig_start = xml.find("<ds:Signature").unwrap();
    let sig_id = &xml[sig_start..]
        .split("Id=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert!(xml.contains(&format!(
        "<xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Target=\"#{sig_id}\">"
    )));
    assert!(xml.contains(&format!(
        "<ds:Reference URI=\"#{sig_id}-SignedProperties\" Type=\"http://uri.etsi.org/01903#SignedProperties\">"
    )));
    assert!(xml.contains(&format!(
        "<xades:SignedProperties Id=\"{sig_id}-SignedProperties\">"
    )));
    assert_eq!(
        element_text(xml, "xades:SigningTime"),
        "2026-10-29T12:00:00Z"
    );
    let digest = element_text(element_text(xml, "xades:CertDigest"), "ds:DigestValue");
    assert_eq!(
        STANDARD.decode(digest).unwrap(),
        Sha256::digest(signer.cert.to_der().unwrap()).to_vec()
    );
    assert!(
        xml.contains("<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>")
    );
    assert!(!xml.contains("UnsignedProperties"));
    let checked = verify(&signed).unwrap();
    assert_eq!(checked[0].cert, signer.cert);
}

#[test]
fn xades_t_timestamp_over_signature_value() {
    let signer = entry("user-gost2015-sign");
    let signed = sign(
        DOC,
        &spec(XadesLevel::T, Vec::new()),
        &signer.key,
        &signer.cert,
        &pki(false),
        NOW,
    )
    .unwrap();
    let xml = text(&signed);
    let tokens = all_base64(xml, "xades:EncapsulatedTimeStamp");
    let [token] = tokens.as_slice() else {
        panic!("{tokens:?}")
    };
    let tst = tsp::verify_token(token).unwrap();
    // The SignatureValue element, canonicalized alone (exclusively): its namespace on it,
    // `&#13;` as `&#xD;`.
    let value = element_text(xml, "ds:SignatureValue").replace("&#13;", "&#xD;");
    let canonical = format!("<ds:SignatureValue xmlns:ds=\"{DSIG}\">{value}</ds:SignatureValue>");
    assert_eq!(tst.imprint, tsa_spec().hash.digest(canonical.as_bytes()));
    assert!(xml.contains(
        "<xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp"
    ));
    assert!(!xml.contains("CertificateValues"));
    verify(&signed).unwrap();
}

#[test]
fn xades_lt_certificate_and_revocation_values() {
    let signer = entry("inter-user-gost2015-sign");
    let chain = vec![cer("inter-gost2015"), cer("root-gost2015")];
    let signed = sign(
        DOC,
        &spec(XadesLevel::Lt, chain.clone()),
        &signer.key,
        &signer.cert,
        &pki(true),
        NOW,
    )
    .unwrap();
    let xml = text(&signed);
    let certs = all_base64(xml, "xades:EncapsulatedX509Certificate");
    let expected: Vec<Vec<u8>> = chain.iter().map(|c| c.to_der().unwrap()).collect();
    assert_eq!(certs, expected);
    // The signer's alone: the root is self-signed, the intermediate names no responder.
    let responses = all_base64(xml, "xades:EncapsulatedOCSPValue");
    assert_eq!(responses.len(), 1);
    assert!(responses.iter().all(|r| r[0] == 0x30));
    let order = [
        "SignatureTimeStamp",
        "CertificateValues",
        "RevocationValues",
    ]
    .map(|name| xml.find(&format!("<xades:{name}")).unwrap());
    assert!(order.is_sorted(), "{order:?}");
    verify(&signed).unwrap();
    // A chain without the issuer.
    let result = sign(
        DOC,
        &spec(XadesLevel::Lt, vec![cer("root-gost2015")]),
        &signer.key,
        &signer.cert,
        &pki(true),
        NOW,
    );
    assert!(matches!(result, Err(XadesError::NoIssuer(_))), "{result:?}");
}

#[test]
fn xades_signature_verifies() {
    let signer = entry("user-gost2015-sign");
    for level in [XadesLevel::B, XadesLevel::T] {
        let signed = sign(
            DOC,
            &spec(level, Vec::new()),
            &signer.key,
            &signer.cert,
            &pki(false),
            NOW,
        )
        .unwrap();
        verify(&signed).unwrap();
        // The signed properties are signed.
        let tampered = text(&signed).replace("2026-10-29T12:00:00Z", "2026-10-29T12:00:01Z");
        assert_eq!(
            verify(tampered.as_bytes()).unwrap_err(),
            XmlError::BadDigest
        );
        // So is the document.
        let tampered = text(&signed).replace("<a>1</a>", "<a>2</a>");
        assert_eq!(
            verify(tampered.as_bytes()).unwrap_err(),
            XmlError::BadDigest
        );
    }
}

#[test]
fn xades_gost2004_and_rsa_uris() {
    for (name, method) in [
        (
            "user-gost2004-sign",
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
        ),
        (
            "user-rsa-sign",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        ),
        (
            "user-gost2015-sign",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
        ),
    ] {
        let signer = entry(name);
        let signed = sign(
            DOC,
            &spec(XadesLevel::B, Vec::new()),
            &signer.key,
            &signer.cert,
            &Offline,
            NOW,
        )
        .unwrap();
        assert!(
            text(&signed).contains(&format!("<ds:SignatureMethod Algorithm=\"{method}\"/>")),
            "{name}"
        );
        verify(&signed).unwrap();
    }
    // A URI that does not fit the key.
    let signer = entry("user-rsa-sign");
    let other = XadesSpec {
        signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"),
        ..spec(XadesLevel::B, Vec::new())
    };
    let result = sign(DOC, &other, &signer.key, &signer.cert, &Offline, NOW);
    assert!(
        matches!(result, Err(XadesError::Xml(XmlError::Constraint(_)))),
        "{result:?}"
    );
}

#[test]
fn xades_tsa_failure_outcome() {
    let signer = entry("inter-user-gost2015-sign");
    let chain = vec![cer("inter-gost2015"), cer("root-gost2015")];
    let result = sign(
        DOC,
        &spec(XadesLevel::T, Vec::new()),
        &signer.key,
        &signer.cert,
        &Offline,
        NOW,
    );
    assert!(matches!(result, Err(XadesError::Tsp(_))), "{result:?}");
    // The TSA answers, the responder does not.
    let result = sign(
        DOC,
        &spec(XadesLevel::Lt, chain),
        &signer.key,
        &signer.cert,
        &pki(false),
        NOW,
    );
    match result {
        Err(XadesError::Ocsp { url, .. }) => assert_eq!(url, OCSP_URL),
        other => panic!("{other:?}"),
    }
    // Without a TSA, T is refused before anything is signed.
    let no_tsa = XadesSpec {
        tsa: None,
        ..spec(XadesLevel::T, Vec::new())
    };
    let result = sign(DOC, &no_tsa, &signer.key, &signer.cert, &Offline, NOW);
    assert!(
        matches!(result, Err(XadesError::Xml(XmlError::Constraint(_)))),
        "{result:?}"
    );
}
