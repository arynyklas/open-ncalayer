//! Actual signature math and exact SOAP consumer binding, never tag-presence tests.
use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{Source, TemporaryStore},
    key::SigAlg,
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
    validation::{CheckStatus, NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use oncl_testkit::{read, synthetic};
use oncl_xml::wsse::{self, SourceWsseSignProfile, WsseVerifyProfile};
use std::{io::Cursor, sync::Arc};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        panic!("offline must not fetch")
    }
}
const SOAP: &str = "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Header><m:note xmlns:m='urn:note'>uncovered</m:note></s:Header><s:Body><m:request xmlns:m='urn:app'>protected</m:request></s:Body></s:Envelope>";
fn signed(xml: &[u8], profile: &SourceWsseSignProfile) -> Vec<u8> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let f = synthetic("user-rsa-sign");
    let mut key = oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0);
    let mut out = Vec::new();
    wsse::sign_source(
        Source::sequential(&mut Cursor::new(xml), None),
        profile,
        &mut key,
        &store,
        &mut out,
        &mut scope,
    )
    .unwrap();
    out
}
fn check(
    xml: &[u8],
    profile: &WsseVerifyProfile,
) -> Result<wsse::WsseVerification, oncl_xml::XmlSourceError> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let anchors = CaSet::new(vec![]);
    let validation = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    wsse::verify_source(
        Source::sequential(&mut Cursor::new(xml), None),
        profile,
        &store,
        &validation,
        &NetworkPolicy::deny_all(),
        &mut scope,
    )
}
#[test]
fn signed_body_is_used_body() {
    let bytes = signed(SOAP.as_bytes(), &SourceWsseSignProfile::default());
    let report = check(&bytes, &WsseVerifyProfile::default()).unwrap();
    assert_eq!(
        report.xml.validation.signers[0].signature,
        CheckStatus::Passed
    );
    assert_eq!(report.xml.signatures()[0].algorithm, SigAlg::RsaSha256);
    assert!(report.signers()[0].body_digest_matches());
    let xml = String::from_utf8(bytes).unwrap();
    let changed = check(
        xml.replace(">protected<", ">tampered<").as_bytes(),
        &WsseVerifyProfile::default(),
    )
    .unwrap();
    assert_eq!(changed.xml.validation.verdict, Verdict::Invalid);
    assert!(!changed.signers()[0].body_digest_matches());
    let uncovered = check(
        xml.replace(">uncovered<", ">changed<").as_bytes(),
        &WsseVerifyProfile::default(),
    )
    .unwrap();
    assert_eq!(
        uncovered.xml.validation.signers[0].signature,
        CheckStatus::Passed
    );
    assert!(uncovered.signers()[0].covered_headers().is_empty());
}
#[test]
fn duplicate_body_id_and_wrapping() {
    let xml =
        String::from_utf8(signed(SOAP.as_bytes(), &SourceWsseSignProfile::default())).unwrap();
    let body = xml.find("<s:Body").unwrap();
    let end = xml.find("</s:Body>").unwrap() + "</s:Body>".len();
    let old = &xml[body..end];
    let moved = xml.replacen(old, "<s:Body><forged/></s:Body>", 1).replace(
        "</s:Header>",
        &format!("<m:wrapper xmlns:m='urn:evil'>{old}</m:wrapper></s:Header>"),
    );
    assert!(check(moved.as_bytes(), &WsseVerifyProfile::default()).is_err());
    let duplicate = xml.replace("</s:Header>", "<m:fake xmlns:m='urn:evil' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' u:Id='oncl-body'/></s:Header>");
    assert!(check(duplicate.as_bytes(), &WsseVerifyProfile::default()).is_err());
}
#[test]
fn multiple_headers_namespaces() {
    let xml = SOAP
        .replace(
            "</s:Header>",
            "<x:other xmlns:x='urn:other'>legitimate</x:other></s:Header>",
        )
        .replace("<s:", "<env:")
        .replace("</s:", "</env:")
        .replace("xmlns:s=", "xmlns:env=");
    let signed = signed(xml.as_bytes(), &SourceWsseSignProfile::default());
    let report = check(&signed, &WsseVerifyProfile::default()).unwrap();
    assert_eq!(
        report.xml.validation.signers[0].signature,
        CheckStatus::Passed
    );
    assert!(report.signers()[0].body_digest_matches());
    let xml = String::from_utf8(signed).unwrap();
    assert!(
        check(
            xml.replace(
                "http://schemas.xmlsoap.org/soap/envelope/",
                "urn:wrong-soap"
            )
            .as_bytes(),
            &WsseVerifyProfile::default()
        )
        .is_err()
    );
    assert!(
        check(
            xml.replace("URI=\"#oncl-body\"", "URI=\"#%6fncl-body\"")
                .as_bytes(),
            &WsseVerifyProfile::default()
        )
        .is_err()
    );
}

#[test]
fn binary_token_soap12_role_timestamp_and_covered_header() {
    use wsse::{SoapVersion, TokenReference, WsseTimestamp};
    let now = time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap();
    let mut profile = SourceWsseSignProfile::default();
    profile.verification.soap = SoapVersion::Soap12;
    profile.verification.role = Some("urn:service:recipient".into());
    profile.verification.timestamp.required = true;
    profile.verification.required_headers = vec!["routing".into()];
    profile.token_reference = TokenReference::BinarySecurityToken;
    profile.timestamp = Some(WsseTimestamp {
        id: "freshness".into(),
        created: now - time::Duration::SECOND,
        expires: now + time::Duration::MINUTE,
    });
    let xml = SOAP.replace("http://schemas.xmlsoap.org/soap/envelope/", SoapVersion::Soap12.namespace()).replace("<m:note", "<m:note xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' u:Id='routing'");
    let bytes = signed(xml.as_bytes(), &profile);
    let report = check(&bytes, &profile.verification).unwrap();
    assert_eq!(
        report.xml.validation.signers[0].signature,
        CheckStatus::Passed
    );
    assert_eq!(report.signers()[0].covered_headers().len(), 1);
    assert!(report.signers()[0].covered_timestamp().is_some());
    assert!(report.xml.validation.signers[0].proof_time.is_none());
    let xml = String::from_utf8(bytes).unwrap();
    assert!(check(xml.as_bytes(), &WsseVerifyProfile::default()).is_err());
    for changed in [
        xml.replace("urn:service:recipient", "urn:wrong:recipient"),
        xml.replace("ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"", "ValueType=\"urn:wrong\""),
        xml.replace("URI=\"#oncl-token\"", "URI=\"#oncl-body\""),
        xml.replace("URI=\"#freshness\"", "URI=\"#routing\""),
        xml.replace("u:Id='routing'", "u:Id='routing' Id='alias'"),
    ] { assert!(check(changed.as_bytes(), &profile.verification).is_err()); }
}

#[test]
fn valid_signature_with_wrong_token_is_not_accepted_and_other_roles_are_not_first_valid() {
    let original =
        String::from_utf8(signed(SOAP.as_bytes(), &SourceWsseSignProfile::default())).unwrap();
    let f = synthetic("user-gost2015-sign");
    let key = oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0);
    use base64::Engine as _;
    use der::Encode;
    let replacement = base64::engine::general_purpose::STANDARD.encode(key.cert.to_der().unwrap());
    let start = original.find("<wsse:KeyIdentifier").unwrap();
    let text = original[start..].find('>').unwrap() + start + 1;
    let end = original[text..].find("</wsse:KeyIdentifier>").unwrap() + text;
    let changed = format!("{}{}{}", &original[..text], replacement, &original[end..]);
    let checked = check(changed.as_bytes(), &WsseVerifyProfile::default());
    assert!(checked.is_err() || checked.unwrap().xml.validation.verdict == Verdict::Invalid);
    let start = original.find("<wsse:Security ").unwrap();
    let end = original.find("</wsse:Security>").unwrap() + "</wsse:Security>".len();
    let security = &original[start..end];
    let duplicate = original.replace("</s:Header>", &format!("{security}</s:Header>"));
    assert!(check(duplicate.as_bytes(), &WsseVerifyProfile::default()).is_err());
    let moved = original.replace(security, "").replace(
        "</s:Header>",
        &format!("<m:other xmlns:m='urn:wrapped'>{security}</m:other></s:Header>"),
    );
    assert!(check(moved.as_bytes(), &WsseVerifyProfile::default()).is_err());
    let unsupported = original.replace("</wsse:Security>", "<u:SignatureConfirmation xmlns:u='http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd'/></wsse:Security>");
    assert!(check(unsupported.as_bytes(), &WsseVerifyProfile::default()).is_err());
}

#[test]
fn preexisting_body_id_lexical_bytes_and_empty_header_are_preserved() {
    let xml = SOAP.replace("<s:Body>", "<s:Body xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' u:Id='existing' a='&quot;'>");
    let bytes = signed(xml.as_bytes(), &SourceWsseSignProfile::default());
    let result = check(&bytes, &WsseVerifyProfile::default()).unwrap();
    assert_eq!(
        result.xml.validation.signers[0].signature,
        CheckStatus::Passed
    );
    let source_body = &xml[xml.find("<s:Body").unwrap()..];
    assert!(bytes.ends_with(source_body.as_bytes()));
    for xml in [
        "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Header/><s:Body/></s:Envelope>",
        "<Envelope xmlns='http://schemas.xmlsoap.org/soap/envelope/'><Body/></Envelope>",
    ] {
        let bytes = signed(xml.as_bytes(), &SourceWsseSignProfile::default());
        assert_eq!(
            check(&bytes, &WsseVerifyProfile::default())
                .unwrap()
                .xml
                .validation
                .signers[0]
                .signature,
            CheckStatus::Passed
        );
    }
}

#[test]
fn mathematically_valid_x509data_is_not_a_wsse_token_binding() {
    let original =
        String::from_utf8(signed(SOAP.as_bytes(), &SourceWsseSignProfile::default())).unwrap();
    let parsed = roxmltree::Document::parse(&original).unwrap();
    let info = parsed
        .descendants()
        .find(|n| n.tag_name().name() == "KeyInfo")
        .unwrap();
    let token = parsed
        .descendants()
        .find(|n| n.tag_name().name() == "KeyIdentifier")
        .unwrap()
        .text()
        .unwrap();
    let changed = format!(
        "{}<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{token}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>{}",
        &original[..info.range().start],
        &original[info.range().end..]
    );
    assert!(
        check(changed.as_bytes(), &WsseVerifyProfile::default()).is_err(),
        "XMLDSig math alone is not STR association"
    );
}

#[test]
fn pinned_external_ncanode_fixture_math_is_valid_but_expired_pki_is_not_trust() {
    let report = check(
        include_bytes!("support/wsse-ncanode.xml"),
        &WsseVerifyProfile::default(),
    )
    .unwrap();
    assert_eq!(
        report.xml.validation.signers[0].signature,
        CheckStatus::Passed
    );
    assert!(report.signers()[0].body_digest_matches());
    assert_ne!(report.xml.validation.verdict, Verdict::Valid);
    assert_eq!(
        report.xml.validation.signers[0].validity,
        CheckStatus::Failed
    );
}

#[test]
fn used_body_borrow_is_original_scope_bound_and_cancellation_is_not_invalid_signature() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Cancellable(AtomicBool);
    impl OperationControl for Cancellable {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let bytes = signed(SOAP.as_bytes(), &SourceWsseSignProfile::default());
    let limits = ResourceLimits {
        max_in_flight: 2,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let control = Arc::new(Cancellable(AtomicBool::new(false)));
    let mut scope = budget.begin(limits.clone(), control.clone()).unwrap();
    let foreign = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let anchors = CaSet::new(vec![]);
    let validation = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let mut report = wsse::verify_source(
        Source::sequential(&mut Cursor::new(&bytes), None),
        &WsseVerifyProfile::default(),
        &store,
        &validation,
        &NetworkPolicy::deny_all(),
        &mut scope,
    )
    .unwrap();
    let headroom = scope.reserve_metadata(48 * 1024 * 1024).expect(
        "coverage must retain the small closed source/geometry, not the transient parser index",
    );
    drop(headroom);
    let mut body = [0; 16];
    assert!(report.xml.facts.wsse().unwrap().used_body_region().len > 0);
    assert!(
        report
            .xml
            .facts
            .read_used_soap_body(0, &mut body, &foreign)
            .is_err()
    );
    assert!(
        report
            .xml
            .facts
            .read_used_soap_body(0, &mut body, &scope)
            .unwrap()
            > 0
    );
    control.0.store(true, Ordering::SeqCst);
    assert!(matches!(
        report.xml.facts.read_used_soap_body(0, &mut body, &scope),
        Err(oncl_xml::XmlSourceError::Processing(
            ProcessingError::Cancelled
        ))
    ));
}

#[test]
fn recognized_timestamp_outside_security_is_not_unsigned_application_metadata() {
    let original =
        String::from_utf8(signed(SOAP.as_bytes(), &SourceWsseSignProfile::default())).unwrap();
    let changed = original.replace("</s:Header>", "<u:Timestamp xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' u:Id='unbound'><u:Created>2026-11-03T12:00:00Z</u:Created><u:Expires>2026-11-03T12:01:00Z</u:Expires></u:Timestamp></s:Header>");
    assert!(check(changed.as_bytes(), &WsseVerifyProfile::default()).is_err());
}

#[test]
fn generic_soap_xmldsig_keeps_its_non_wsse_contract() {
    let f = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0);
    let xml = SOAP.replace("<s:Body>", "<s:Body Id='generic-body'>");
    let signed = oncl_xml::sign_element(
        xml.as_bytes(),
        "/SOAP-ENV:Envelope/SOAP-ENV:Body",
        None,
        &key.key,
        &key.cert,
    )
    .unwrap();
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let anchors = CaSet::new(vec![]);
    let validation = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let report = oncl_xml::verify_source(
        Source::sequential(&mut Cursor::new(&signed), None),
        &oncl_xml::XmlVerifyProfile::default(),
        &store,
        &validation,
        &NetworkPolicy::deny_all(),
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert!(report.facts.wsse().is_none());
    assert!(check(&signed, &WsseVerifyProfile::default()).is_err());
}

#[test]
fn malformed_unreferenced_x509_token_is_not_ignored_or_free_application_data() {
    let original =
        String::from_utf8(signed(SOAP.as_bytes(), &SourceWsseSignProfile::default())).unwrap();
    let token = format!(
        "<wsse:BinarySecurityToken xmlns:wsu='{}' wsu:Id='fake-certificate' EncodingType='{}' ValueType='{}'>QUJD</wsse:BinarySecurityToken>",
        wsse::WSU_NS,
        wsse::BASE64_BINARY,
        wsse::X509_V3
    );
    let changed = original.replace("</wsse:Security>", &format!("{token}</wsse:Security>"));
    assert!(check(changed.as_bytes(), &WsseVerifyProfile::default()).is_err());
}
