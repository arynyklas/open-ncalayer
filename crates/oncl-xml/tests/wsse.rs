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
    let anchors = CaSet::new(vec![
        oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
    ]);
    let validation = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let prepared = wsse::prepare_source(
        Source::sequential(&mut Cursor::new(xml), None),
        profile,
        &store,
        &mut scope,
    )
    .unwrap();
    let mut stage = store.stage(&mut scope).unwrap();
    let mut output = oncl_pki::io::XmlSignatureOutput::new(&mut stage, &scope).unwrap();
    let (_, report) = wsse::sign_prepared(
        prepared,
        &mut key,
        &validation,
        &NetworkPolicy::deny_all(),
        None,
        &mut output,
        &mut scope,
    )
    .unwrap();
    drop(report);
    output.finish(&scope).unwrap();
    let mut out = Vec::new();
    stage.copy_to(&mut out).unwrap();
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
#[ignore = "needs cargo xtask fetch-fixtures"]
fn pinned_external_ncanode_fixture_math_is_valid_but_expired_pki_is_not_trust() {
    let report = check(
        &oncl_testkit::read(oncl_testkit::ncanode("wsse-ncanode.xml")),
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

#[test]
fn fix_header_creation_uses_soap_namespace_not_body_local_binding() {
    for body in [
        "<b:Body xmlns:b='http://schemas.xmlsoap.org/soap/envelope/'><m:request xmlns:m='urn:app' a='&quot;'>protected</m:request></b:Body>",
        "<Body xmlns='http://schemas.xmlsoap.org/soap/envelope/'><m:request xmlns:m='urn:app' a='&quot;'>protected</m:request></Body>",
    ] {
        let input = format!(
            "<e:Envelope xmlns:e='http://schemas.xmlsoap.org/soap/envelope/'>{body}</e:Envelope>"
        );
        let output = signed(input.as_bytes(), &SourceWsseSignProfile::default());
        assert!(
            String::from_utf8_lossy(&output)
                .contains("<m:request xmlns:m='urn:app' a='&quot;'>protected</m:request>")
        );
        assert_eq!(
            check(&output, &WsseVerifyProfile::default())
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
fn fix_foreign_application_container_local_names_are_not_soap() {
    let input = SOAP
        .replace(
            "</s:Header>",
            "<m:Header xmlns:m='urn:application'>application header</m:Header></s:Header>",
        )
        .replace(
            ">protected<",
            "><m:Envelope><m:Header/><m:Body>protected</m:Body></m:Envelope><",
        );
    let output = signed(input.as_bytes(), &SourceWsseSignProfile::default());
    assert_eq!(
        check(&output, &WsseVerifyProfile::default())
            .unwrap()
            .xml
            .validation
            .signers[0]
            .signature,
        CheckStatus::Passed
    );
    let nested = input
        .replace("<m:Body>", "<s:Body>")
        .replace("</m:Body>", "</s:Body>");
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    assert!(
        wsse::prepare_source(
            Source::sequential(&mut Cursor::new(nested), None),
            &SourceWsseSignProfile::default(),
            &store,
            &mut scope
        )
        .is_err()
    );
}

#[test]
fn fix_unicode_header_and_timestamp_ids_have_one_bare_fragment_contract() {
    let now = time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap();
    let mut p = SourceWsseSignProfile {
        body_id: "body-é".into(),
        ..Default::default()
    };
    p.verification.required_headers = vec!["route-é".into()];
    p.timestamp = Some(wsse::WsseTimestamp {
        id: "ts-é".into(),
        created: now - time::Duration::SECOND,
        expires: now + time::Duration::MINUTE,
    });
    let input = SOAP.replace(
        "<m:note",
        &format!("<m:note xmlns:u='{}' u:Id='route-é'", wsse::WSU_NS),
    );
    let output = signed(input.as_bytes(), &p);
    let text = std::str::from_utf8(&output).unwrap();
    for id in ["body-é", "route-é", "ts-é"] {
        assert!(text.contains(&format!("URI=\"#{id}\"")));
    }
    assert_eq!(
        check(&output, &p.verification)
            .unwrap()
            .xml
            .validation
            .signers[0]
            .signature,
        CheckStatus::Passed
    );
}

struct CountingSigner {
    entry: oncl_pki::pkcs12::KeyEntry,
    uses: usize,
}
impl CountingSigner {
    fn new() -> Self {
        let f = synthetic("user-rsa-sign");
        Self {
            entry: oncl_pki::pkcs12::load(&read(&f.path), &f.password)
                .unwrap()
                .remove(0),
            uses: 0,
        }
    }
}
impl oncl_pki::key::DigestSigner for CountingSigner {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        &self.entry.cert
    }
    fn algorithm(&self) -> SigAlg {
        SigAlg::RsaSha256
    }
    fn sign_digest(
        &mut self,
        digest: &oncl_pki::digest::DigestValue,
    ) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
        self.uses += 1;
        self.entry.key.sign_digest(SigAlg::RsaSha256, digest)
    }
}

#[test]
fn fix_public_create_time_policy_is_mandatory_at_private_boundary() {
    let now = time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap();
    for existing in [false, true] {
        for prepared_boundary in [false, true] {
            let limits = ResourceLimits::default();
            let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
            let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
            let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
            let mut signer = CountingSigner::new();
            let mut p = SourceWsseSignProfile::default();
            let mut input = SOAP.to_owned();
            if existing {
                input = input.replace("</s:Header>", &format!("<w:Security xmlns:w='{}'><u:Timestamp xmlns:u='{}' u:Id='future'><u:Created>2026-11-04T12:00:00Z</u:Created><u:Expires>2026-11-04T12:01:00Z</u:Expires></u:Timestamp></w:Security></s:Header>", wsse::WSSE_NS, wsse::WSU_NS));
            } else {
                p.timestamp = Some(wsse::WsseTimestamp {
                    id: "future".into(),
                    created: now + time::Duration::MINUTE,
                    expires: now + time::Duration::minutes(2),
                });
            }
            let failed = if prepared_boundary {
                let prepared = wsse::prepare_source(
                    Source::sequential(&mut Cursor::new(&input), None),
                    &p,
                    &store,
                    &mut scope,
                )
                .unwrap();
                let anchors = CaSet::new(vec![]);
                let ctx = ValidationContext {
                    policy: ValidationPolicy::OfflineReport,
                    now,
                    anchors: &anchors,
                    intermediates: &[],
                    http: &Offline,
                };
                let mut stage = store.stage(&mut scope).unwrap();
                let mut output = oncl_pki::io::XmlSignatureOutput::new(&mut stage, &scope).unwrap();
                wsse::sign_prepared(
                    prepared,
                    &mut signer,
                    &ctx,
                    &NetworkPolicy::deny_all(),
                    None,
                    &mut output,
                    &mut scope,
                )
                .is_err()
            } else {
                wsse::sign_source(
                    Source::sequential(&mut Cursor::new(&input), None),
                    &p,
                    &mut signer,
                    &store,
                    &mut Vec::new(),
                    &mut scope,
                )
                .is_err()
            };
            assert!(failed);
            assert_eq!(
                signer.uses, 0,
                "existing={existing}, prepared={prepared_boundary}"
            );
        }
    }
}

#[test]
fn fix_soap12_none_is_not_a_host_processing_role() {
    let mut p = SourceWsseSignProfile::default();
    p.verification.soap = wsse::SoapVersion::Soap12;
    p.verification.role = Some("http://www.w3.org/2003/05/soap-envelope/role/none".into());
    let input = SOAP.replace(
        "http://schemas.xmlsoap.org/soap/envelope/",
        p.verification.soap.namespace(),
    );
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut signer = CountingSigner::new();
    assert!(
        wsse::sign_source(
            Source::sequential(&mut Cursor::new(&input), None),
            &p,
            &mut signer,
            &store,
            &mut Vec::new(),
            &mut scope
        )
        .is_err()
    );
    assert_eq!(signer.uses, 0);
}

fn canonical_test_node(xml: &str, id: Option<&str>) -> Vec<u8> {
    let parsed = roxmltree::Document::parse(xml).unwrap();
    let soap_namespace = parsed.root_element().tag_name().namespace().unwrap();
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut doc = oncl_xml::XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml), None),
        &oncl_xml::XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    let node = match id {
        Some(id) => doc.lookup_id(id).unwrap().unwrap(),
        None => doc
            .select_xpath(
                "/s:Envelope/s:Header/w:Security/ds:Signature/ds:SignedInfo",
                &[
                    ("s", soap_namespace),
                    ("w", wsse::WSSE_NS),
                    ("ds", "http://www.w3.org/2000/09/xmldsig#"),
                ],
                &mut scope,
            )
            .unwrap()
            .unwrap(),
    };
    let mut out = Vec::new();
    doc.canonicalize(
        Some(&node),
        oncl_xml::C14n::Exclusive,
        oncl_xml::C14nProfile::Standard,
        &mut out,
        &mut scope,
    )
    .unwrap();
    out
}

fn resign_timestamp_fixture(mut xml: String) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        oncl_pki::key::HashAlg::Sha256.digest(&canonical_test_node(&xml, Some("freshness"))),
    );
    let parsed = roxmltree::Document::parse(&xml).unwrap();
    let reference = parsed
        .descendants()
        .find(|n| n.tag_name().name() == "Reference" && n.attribute("URI") == Some("#freshness"))
        .unwrap();
    let digest = reference
        .children()
        .find(|n| n.tag_name().name() == "DigestValue")
        .unwrap()
        .range();
    xml.replace_range(
        digest,
        &format!("<ds:DigestValue>{encoded}</ds:DigestValue>"),
    );
    let info = canonical_test_node(&xml, None);
    let key = CountingSigner::new();
    let signature = key.entry.key.sign(SigAlg::RsaSha256, &info).unwrap();
    key.entry
        .key
        .public_key()
        .verify(SigAlg::RsaSha256, &info, &signature)
        .unwrap();
    let parsed = roxmltree::Document::parse(&xml).unwrap();
    let range = parsed
        .descendants()
        .find(|n| n.tag_name().name() == "SignatureValue")
        .unwrap()
        .range();
    xml.replace_range(
        range,
        &format!(
            "<ds:SignatureValue>{}</ds:SignatureValue>",
            base64::engine::general_purpose::STANDARD.encode(signature)
        ),
    );
    xml
}

#[test]
fn fix_complete_signed_timestamp_character_value_and_framing() {
    let now = time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap();
    let p = SourceWsseSignProfile {
        timestamp: Some(wsse::WsseTimestamp {
            id: "freshness".into(),
            created: now - time::Duration::SECOND,
            expires: now + time::Duration::MINUTE,
        }),
        ..Default::default()
    };
    let original = String::from_utf8(signed(SOAP.as_bytes(), &p)).unwrap();
    assert_eq!(
        check(original.as_bytes(), &p.verification)
            .unwrap()
            .xml
            .validation
            .signers[0]
            .signature,
        CheckStatus::Passed
    );
    for change in [
        original.replace("</wsu:Created>", "<!--split-->junk</wsu:Created>"),
        original.replace("</wsu:Expires>", "<!--split-->junk</wsu:Expires>"),
        original.replace("<wsu:Created>", "surplus-character-content<wsu:Created>"),
    ] {
        let actual_signed = resign_timestamp_fixture(change);
        assert!(check(actual_signed.as_bytes(), &p.verification).is_err());
    }
}

#[test]
fn fix_comments_in_valid_token_or_signed_timestamp_are_not_free_metadata() {
    let now = time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap();
    let p = SourceWsseSignProfile {
        token_reference: wsse::TokenReference::BinarySecurityToken,
        timestamp: Some(wsse::WsseTimestamp {
            id: "freshness".into(),
            created: now - time::Duration::SECOND,
            expires: now + time::Duration::MINUTE,
        }),
        ..Default::default()
    };
    let original = String::from_utf8(signed(SOAP.as_bytes(), &p)).unwrap();
    for marker in [
        "</wsse:BinarySecurityToken>",
        "</wsu:Created>",
        "</wsu:Timestamp>",
    ] {
        let changed = original.replace(marker, &format!("<!--application-->{marker}"));
        let limits = ResourceLimits {
            input_bytes: SOAP.len() as u64,
            ..Default::default()
        };
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
        let result = oncl_xml::capture_signed_input(
            Source::sequential(&mut Cursor::new(changed.as_bytes()), None),
            &p.verification.xml,
            &store,
            &mut scope,
        );
        assert!(
            result.is_err(),
            "typed metadata must not credit arbitrary comments at {marker}"
        );
        assert_eq!(scope.progress().bytes_in, changed.len() as u64);
    }
}

fn capture_test_counts(
    xml: &str,
    p: &WsseVerifyProfile,
    input_bytes: u64,
) -> Result<(u64, u64), oncl_xml::XmlSourceError> {
    let limits = ResourceLimits {
        input_bytes,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let result = oncl_xml::capture_signed_input(
        Source::sequential(&mut Cursor::new(xml.as_bytes()), None),
        &p.xml,
        &store,
        &mut scope,
    );
    assert_eq!(scope.progress().bytes_in, xml.len() as u64);
    result.map(|owner| {
        assert_eq!(
            owner.document_bytes() + owner.container_bytes(),
            owner.len()
        );
        (owner.document_bytes(), owner.container_bytes())
    })
}

#[test]
fn fix_raw_wrapper_width_and_checked_framing_total_cap() {
    for ordinary in [false, true] {
        let input = if ordinary {
            SOAP.to_owned()
        } else {
            SOAP.replace("<m:note xmlns:m='urn:note'>uncovered</m:note>", "")
        };
        let original =
            String::from_utf8(signed(input.as_bytes(), &SourceWsseSignProfile::default())).unwrap();
        let mut p = WsseVerifyProfile::default();
        p.xml.max_metadata_bytes = 4096;
        let (document, _) = capture_test_counts(&original, &p, 1 << 20).unwrap();
        let parsed = roxmltree::Document::parse(&original).unwrap();
        let header = parsed
            .descendants()
            .find(|n| n.tag_name().name() == "Header")
            .unwrap()
            .range();
        let security = parsed
            .descendants()
            .find(|n| n.tag_name().name() == "Security")
            .unwrap()
            .range();
        let framing = |range: std::ops::Range<usize>| {
            let text = &original[range];
            text.find('>').unwrap() + 1 + text.len() - text.rfind("</").unwrap()
        };
        let total = framing(security.clone()) + if ordinary { 0 } else { framing(header.clone()) };
        for (name, target) in [("security", security), ("header", header)] {
            let at = target.start + original[target.clone()].find('>').unwrap();
            let pad = 4096 - total;
            let mut exact = original.clone();
            exact.insert_str(at, &" ".repeat(pad));
            if ordinary && name == "header" {
                assert_eq!(
                    capture_test_counts(&exact, &p, document + pad as u64)
                        .unwrap()
                        .0,
                    document + pad as u64
                );
                assert!(capture_test_counts(&exact, &p, document + pad as u64 - 1).is_err());
            } else {
                assert_eq!(
                    capture_test_counts(&exact, &p, document).unwrap().0,
                    document
                );
                let mut over = exact;
                over.insert(at, ' ');
                assert!(
                    capture_test_counts(&over, &p, document).is_err(),
                    "{name} ordinary={ordinary}: raw framing cap+1 was credited"
                );
            }
        }
    }
}

#[test]
fn fix_role_none_carrier_is_preserved_but_never_selected() {
    let mut p = SourceWsseSignProfile::default();
    p.verification.soap = wsse::SoapVersion::Soap12;
    let carrier = format!(
        "<w:Security xmlns:w='{}' xmlns:e='{}' e:role='http://www.w3.org/2003/05/soap-envelope/role/none'/>",
        wsse::WSSE_NS,
        p.verification.soap.namespace()
    );
    let input = SOAP
        .replace(
            "http://schemas.xmlsoap.org/soap/envelope/",
            p.verification.soap.namespace(),
        )
        .replace("</s:Header>", &format!("{carrier}</s:Header>"));
    let bytes = signed(input.as_bytes(), &p);
    assert!(std::str::from_utf8(&bytes).unwrap().contains(&carrier));
    let report = check(&bytes, &p.verification).unwrap();
    assert_eq!(report.signers().len(), 1);
    assert!(report.signers()[0].selected_recipient());
    assert_eq!(report.signers()[0].processing_role(), "");
}

#[test]
fn sizing_unicode_many_headers_timestamp_exact_fit_and_one_byte_short() {
    use base64::Engine as _;
    let now = time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap();
    for soap in [wsse::SoapVersion::Soap11, wsse::SoapVersion::Soap12] {
        let ids: Vec<_> = (0..128).map(|i| format!("route-é-{i:03}")).collect();
        let headers = ids
            .iter()
            .map(|id| format!("<h:route u:Id='{id}'>real covered route</h:route>"))
            .collect::<String>();
        let input = format!(
            "<e:Envelope xmlns:e='{}' xmlns:h='urn:route' xmlns:u='{}'><e:Header>{headers}</e:Header><b:Body xmlns:b='{}' u:Id='body-é'><m:request xmlns:m='urn:app'>protected</m:request></b:Body></e:Envelope>",
            soap.namespace(),
            wsse::WSU_NS,
            soap.namespace()
        );
        let mut p = SourceWsseSignProfile::default();
        p.verification.soap = soap;
        p.verification.required_headers = ids;
        // Select the actual 64-KiB component profile; don't combine all default
        // parser/signer scratch maxima or widen the operation's metadata quota.
        p.verification.xml.max_metadata_bytes = 64 * 1024;
        p.timestamp = Some(wsse::WsseTimestamp {
            id: "time-é".into(),
            created: now - time::Duration::SECOND,
            expires: now + time::Duration::MINUTE,
        });
        let original = signed(input.as_bytes(), &p);
        let parsed = roxmltree::Document::parse(std::str::from_utf8(&original).unwrap()).unwrap();
        let security = parsed
            .descendants()
            .find(|n| {
                n.tag_name().namespace() == Some(wsse::WSSE_NS) && n.tag_name().name() == "Security"
            })
            .unwrap();
        let content = security
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|n| n.range().len())
            .sum::<usize>();
        let signature = parsed
            .descendants()
            .find(|n| n.tag_name().name() == "SignatureValue")
            .unwrap();
        let actual = base64::engine::general_purpose::STANDARD
            .decode(signature.text().unwrap())
            .unwrap()
            .len();
        let key = CountingSigner::new();
        let public_bound = key
            .entry
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .unwrap()
            .len();
        let fitting = (content + public_bound.div_ceil(3) * 4 - actual.div_ceil(3) * 4)
            .max(canonical_test_node(std::str::from_utf8(&original).unwrap(), None).len());
        for short in [false, true] {
            let mut selected = p.clone();
            selected.verification.xml.max_metadata_bytes = fitting - usize::from(short);
            let limits = ResourceLimits::default();
            let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
            let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
            let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
            let prepared = wsse::prepare_source(
                Source::sequential(&mut Cursor::new(&input), None),
                &selected,
                &store,
                &mut scope,
            )
            .unwrap();
            let anchors = CaSet::new(vec![
                oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
            ]);
            let validation = ValidationContext {
                policy: ValidationPolicy::OfflineReport,
                now,
                anchors: &anchors,
                intermediates: &[],
                http: &Offline,
            };
            let mut signer = CountingSigner::new();
            let mut stage = store.stage(&mut scope).unwrap();
            let mut output = oncl_pki::io::XmlSignatureOutput::new(&mut stage, &scope).unwrap();
            let result = wsse::sign_prepared(
                prepared,
                &mut signer,
                &validation,
                &NetworkPolicy::deny_all(),
                None,
                &mut output,
                &mut scope,
            );
            if short {
                assert!(matches!(
                    result,
                    Err(oncl_xml::XmlSourceError::Processing(
                        ProcessingError::MetadataLimit
                    )) | Err(oncl_xml::XmlSourceError::Xml(oncl_xml::XmlError::TooLarge))
                ));
                assert_eq!(signer.uses, 0);
                drop(output);
                assert!(stage.copy_to(&mut Vec::new()).is_err());
            } else {
                let (_, report) = result.unwrap();
                assert_eq!(signer.uses, 1);
                assert_eq!(report.signers()[0].covered_headers().len(), 128);
                assert!(report.signers()[0].covered_timestamp().is_some());
                assert!(report.signers()[0].body_digest_matches());
                drop(report);
                output.finish(&scope).unwrap();
            }
        }
    }
}
