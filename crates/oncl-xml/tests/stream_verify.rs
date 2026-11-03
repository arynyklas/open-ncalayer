use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{Source, TemporaryStore},
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
    validation::{CheckStatus, NetworkPolicy, ValidationContext, ValidationPolicy},
};
use oncl_testkit::{read, synthetic};
use oncl_xml::{XmlVerifyProfile, sign_element, verify_source};
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
        panic!("offline XML must not fetch")
    }
}
fn signed() -> Vec<u8> {
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let first = sign_element(
        b"<root><a Id='a'>one</a><b Id='b'>two</b><u>plain</u></root>",
        "/root/a",
        None,
        &key.key,
        &key.cert,
    )
    .unwrap();
    sign_element(&first, "/root/b", None, &key.key, &key.cert).unwrap()
}
fn check(
    xml: &[u8],
    profile: &XmlVerifyProfile,
) -> Result<oncl_xml::XmlVerification, oncl_xml::XmlSourceError> {
    let limits = ResourceLimits {
        output_bytes: 0,
        ..ResourceLimits::default()
    };
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
    let result = verify_source(
        Source::sequential(&mut Cursor::new(xml), None),
        profile,
        &store,
        &validation,
        &NetworkPolicy::deny_all(),
        &mut scope,
    );
    assert_eq!(
        scope.progress().bytes_out,
        0,
        "canonical hash is internal work, not an external artifact"
    );
    result
}
#[test]
fn all_signers_and_uncovered_mutation() {
    let bytes = signed();
    let report = check(&bytes, &XmlVerifyProfile::default()).unwrap();
    assert_eq!(report.validation.signers.len(), 2);
    assert!(
        report
            .validation
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
    );
    let xml = String::from_utf8(bytes).unwrap();
    let mutation = xml.replace(">two<", ">TWO<");
    let report = check(mutation.as_bytes(), &XmlVerifyProfile::default()).unwrap();
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.validation.signers[1].signature, CheckStatus::Failed);
    let report = check(
        xml.replace(">plain<", ">PLAIN<").as_bytes(),
        &XmlVerifyProfile::default(),
    )
    .unwrap();
    assert!(
        report
            .validation
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
    );
}
#[test]
fn wrapping_and_duplicate_target_rejected() {
    let xml = String::from_utf8(signed()).unwrap();
    let wrapped = xml.replace("</root>", "<evil Id='a'>forged</evil></root>");
    assert!(check(wrapped.as_bytes(), &XmlVerifyProfile::default()).is_err());
}
#[test]
fn reference_work_budget() {
    let profile = XmlVerifyProfile {
        max_work: 1,
        ..XmlVerifyProfile::default()
    };
    assert!(check(&signed(), &profile).is_err());
}

#[test]
fn indexed_xpath_selects_real_positional_target() {
    use oncl_xml::{XmlDocument, XmlLimits};
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let xml=b"<r xmlns:p='urn:p'><p:a Id='first'/><p:a Id='second'><p:z/></p:a><x><p:a Id='third'/></x></r>";
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    let selected = doc
        .select_xpath("/r/p:a[2]", &[("p", "urn:p")], &mut scope)
        .unwrap()
        .unwrap();
    let expected = doc.lookup_id("second").unwrap().unwrap();
    assert_eq!(
        doc.node_region(&selected).unwrap(),
        doc.node_region(&expected).unwrap()
    );
    let selected = doc
        .select_xpath("//p:a[1]", &[("p", "urn:p")], &mut scope)
        .unwrap()
        .unwrap();
    let expected = doc.lookup_id("first").unwrap().unwrap();
    assert_eq!(
        doc.node_region(&selected).unwrap(),
        doc.node_region(&expected).unwrap()
    );
    assert!(doc.select_xpath("/r/p:a", &[], &mut scope).is_err());
    assert!(
        doc.select_xpath("doc('http://evil')", &[], &mut scope)
            .is_err()
    );
}

#[test]
fn uri_percent_and_supported_xpointer_bind_actual_targets() {
    let xml = String::from_utf8(signed()).unwrap();
    for uri in ["#%61", "#xpointer(id('a'))", "#xpointer(/root/a[1])"] {
        // Changing SignedInfo invalidates signature math; the unchanged
        // independent reference digest must still resolve the same real node.
        let changed = xml.replace("URI=\"#a\"", &format!("URI=\"{uri}\""));
        let report = check(changed.as_bytes(), &XmlVerifyProfile::default()).unwrap();
        assert!(
            report.signatures()[0].references()[0].digest_matches,
            "{uri}"
        );
        assert_eq!(report.validation.signers[0].signature, CheckStatus::Failed);
    }
}

#[cfg(feature = "testing")]
#[test]
fn recognized_xades_proof_is_not_ignored_or_promoted_to_trust() {
    use oncl_pki::tsp::{MockTsa, TsaProfile, TsaSpec};
    use oncl_xml::xades::{XadesLevel, XadesSpec, sign};
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let fixture = synthetic("tsa-gost2015");
    let tsa = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let spec = XadesSpec {
        level: XadesLevel::T,
        tsa: Some(TsaSpec::from(TsaProfile::basics_default())),
        chain: vec![],
        signature_method: None,
        digest_method: None,
    };
    let bytes = sign(
        b"<doc>covered</doc>",
        &spec,
        &key.key,
        &key.cert,
        &MockTsa::new(tsa),
        time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
    )
    .unwrap();
    let report = check(&bytes, &XmlVerifyProfile::default()).unwrap();
    let signer = &report.validation.signers[0];
    assert_eq!(signer.signature, CheckStatus::Passed);
    assert_ne!(signer.timestamp, CheckStatus::NotApplicable);
    assert!(
        signer.proof_time.is_none(),
        "unanchored TSA cannot establish proof time"
    );
    assert_ne!(
        report.validation.verdict,
        oncl_pki::validation::Verdict::Valid
    );
}

#[cfg(feature = "testing")]
#[test]
fn genuine_signature_value_proof_rescues_expiry_only_with_exact_layout_and_host_status() {
    use oncl_pki::{
        http::RouteTransport,
        ocsp::MockOcsp,
        pkcs12::KeyEntry,
        testing::{TestCertSpec, issue_cert},
        tsp::{MockTsa, TsaProfile, TsaSpec},
    };
    use oncl_xml::xades::{XadesLevel, XadesSpec, sign};
    fn key(name: &str) -> KeyEntry {
        let fixture = synthetic(name);
        oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
            .unwrap()
            .remove(0)
    }
    let root = key("root-gost2015.key");
    let mut signer = key("user-gost2015-sign");
    let mut spec = TestCertSpec::from_cert(&signer.cert);
    // Direct-root synthetic leaves intentionally have no AIA. Add the real
    // intermediate fixture's endpoint extensions before issuer-signing them.
    spec.extensions.extend(
        TestCertSpec::from_cert(&key("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    let expired = time::macros::datetime!(2026-01-01 00:00 UTC);
    spec.validity.not_after = x509_cert::time::Time::UtcTime(
        der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
            expired.unix_timestamp() as u64,
        ))
        .unwrap(),
    );
    signer.cert = issue_cert(&root, spec);
    let mut tsa = key("tsa-gost2015");
    let mut tsa_spec = TestCertSpec::from_cert(&tsa.cert);
    tsa_spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    tsa_spec.extensions.extend(
        TestCertSpec::from_cert(&signer.cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    tsa.cert = issue_cert(&root, tsa_spec);
    let proven = time::macros::datetime!(2025-06-01 10:05 UTC);
    let spec = XadesSpec {
        level: XadesLevel::T,
        tsa: Some(TsaSpec::from(TsaProfile::basics_default())),
        chain: vec![],
        signature_method: None,
        digest_method: None,
    };
    let tsa = MockTsa::new(tsa).with_gen_time(proven);
    let signed = sign(
        b"<doc>covered</doc>",
        &spec,
        &signer.key,
        &signer.cert,
        &tsa,
        proven,
    )
    .unwrap();
    let mut responder = key("ocsp-gost2015");
    responder.cert = issue_cert(&root, TestCertSpec::from_cert(&responder.cert));
    let http = RouteTransport::new(vec![(
        "http://ocsp.synthetic.test".to_owned(),
        Arc::new(MockOcsp::new(responder)),
    )]);
    let anchors = CaSet::new(vec![root.cert.clone()]);
    assert_eq!(
        oncl_pki::ocsp::check_issuer_bound(
            &signer.cert,
            &root.cert,
            &anchors,
            &http,
            time::OffsetDateTime::now_utc(),
            oncl_pki::ocsp::TIMEOUT
        )
        .unwrap(),
        oncl_pki::ocsp::CertStatus::Good
    );
    let validate = |xml: &[u8]| {
        let limits = ResourceLimits {
            output_bytes: 0,
            ..ResourceLimits::default()
        };
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
        let ctx = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: time::OffsetDateTime::now_utc(),
            anchors: &anchors,
            intermediates: &[],
            http: &http,
        };
        let report = verify_source(
            Source::sequential(&mut Cursor::new(xml), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::only_endpoints(["http://ocsp.synthetic.test"]).unwrap(),
            &mut scope,
        )
        .unwrap();
        assert_eq!(scope.progress().bytes_out, 0);
        report
    };
    let report = validate(&signed);
    assert_eq!(
        report.validation.verdict,
        oncl_pki::validation::Verdict::Valid,
        "{report:?}"
    );
    assert_eq!(
        report.validation.signers[0]
            .proof_time
            .as_ref()
            .unwrap()
            .at(),
        proven
    );
    assert_eq!(report.validation.signers[0].validity, CheckStatus::Passed);
    let xml = String::from_utf8(signed).unwrap();
    let layout = xml.replace("<ds:SignatureValue>", "<ds:SignatureValue>\n");
    assert_ne!(layout, xml);
    let report = validate(layout.as_bytes());
    assert!(report.validation.signers[0].proof_time.is_none());
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.validation.signers[0].timestamp, CheckStatus::Failed);
    assert_eq!(report.validation.signers[0].validity, CheckStatus::Failed);
    let value_start = xml.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
    // The real legacy emitter has MIME whitespace. Find literal Base64 bytes;
    // replacing its leading newline would merely create malformed Base64.
    let value_end = value_start + xml[value_start..].find("</ds:SignatureValue>").unwrap();
    let mut positions = [0usize; 4];
    let mut found = 0;
    let mut at = value_start;
    while found < positions.len() && at < value_end {
        match xml.as_bytes()[at] {
            b'&' => at += xml[at..value_end].find(';').unwrap() + 1,
            b' ' | b'\t' | b'\r' | b'\n' => at += 1,
            _ => {
                positions[found] = at;
                found += 1;
                at += 1;
            }
        }
    }
    assert_eq!(found, positions.len());
    let mut comment = xml.clone();
    comment.insert_str(positions[1], "<!--canonical comments omitted-->");
    let report = validate(comment.as_bytes());
    assert_eq!(
        report.validation.signers[0]
            .proof_time
            .as_ref()
            .unwrap()
            .at(),
        proven
    );
    let mut pi = xml.clone();
    pi.insert_str(positions[2], "<?layout changed?>");
    let report = validate(pi.as_bytes());
    assert!(report.validation.signers[0].proof_time.is_none());
    assert_eq!(report.validation.signers[0].timestamp, CheckStatus::Failed);
    let mut cr = xml.clone();
    cr.insert_str(positions[3], "&#13;");
    let report = validate(cr.as_bytes());
    assert!(report.validation.signers[0].proof_time.is_none());
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.validation.signers[0].timestamp, CheckStatus::Failed);
    let mut wrong_signature = xml.clone();
    wrong_signature.replace_range(
        positions[0]..positions[0] + 1,
        if &xml[positions[0]..positions[0] + 1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    let report = validate(wrong_signature.as_bytes());
    assert!(report.validation.signers[0].proof_time.is_none());
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Failed);
    assert_eq!(report.validation.signers[0].timestamp, CheckStatus::Failed);
    let other = sign(
        b"<doc>different covered input</doc>",
        &spec,
        &signer.key,
        &signer.cert,
        &tsa,
        proven,
    )
    .unwrap();
    let timestamp = |xml: &str| {
        let parsed = roxmltree::Document::parse(xml).unwrap();
        parsed
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some("http://uri.etsi.org/01903/v1.3.2#")
                    && n.tag_name().name() == "EncapsulatedTimeStamp"
            })
            .unwrap()
            .text()
            .unwrap()
            .to_owned()
    };
    let original = timestamp(&xml);
    let other = timestamp(std::str::from_utf8(&other).unwrap());
    assert_ne!(original, other);
    let wrong_token = xml.replacen(&original, &other, 1);
    let report = validate(wrong_token.as_bytes());
    assert!(report.validation.signers[0].proof_time.is_none());
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.validation.signers[0].timestamp, CheckStatus::Failed);
    assert_eq!(report.validation.signers[0].validity, CheckStatus::Failed);
}

#[test]
fn xpath_signature_filter_is_explicit_and_all_signers_are_real() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use der::Encode;
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let ds = "http://www.w3.org/2000/09/xmldsig#";
    let canonical = oncl_xml::C14n::Inclusive.uri();
    let digest = STANDARD.encode(oncl_pki::key::HashAlg::Sha256.digest(b"<r>data</r>"));
    let info = format!(
        "<ds:SignedInfo xmlns:ds=\"{ds}\"><ds:CanonicalizationMethod Algorithm=\"{canonical}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm=\"{canonical}\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let value = STANDARD.encode(
        key.key
            .sign(oncl_pki::key::SigAlg::RsaSha256, info.as_bytes())
            .unwrap(),
    );
    let certificate = STANDARD.encode(key.cert.to_der().unwrap());
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{ds}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"
    );
    let xml = format!("<r>data{signature}{signature}</r>");
    let report = check(xml.as_bytes(), &XmlVerifyProfile::default()).unwrap();
    assert_eq!(report.validation.signers.len(), 2);
    assert!(
        report
            .validation
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
    );
    let denied = xml.replace(
        "http://www.w3.org/TR/1999/REC-xpath-19991116",
        "http://www.w3.org/TR/1999/REC-xslt-19991116",
    );
    assert!(check(denied.as_bytes(), &XmlVerifyProfile::default()).is_err());
    let mutation = xml.replacen(">data<", ">DATA<", 1);
    let report = check(mutation.as_bytes(), &XmlVerifyProfile::default()).unwrap();
    assert!(
        report
            .validation
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Failed)
    );
}

#[test]
fn existing_independent_kalkan_signatures_use_explicit_legacy_profile() {
    for file in ["xmldsig-signed-rsa.xml", "xmldsig-signed-rsa-gost2015.xml"] {
        let xml = read(oncl_testkit::ncanode(file));
        let profile = XmlVerifyProfile {
            canonicalization: oncl_xml::C14nProfile::KalkanLegacy,
            ..XmlVerifyProfile::default()
        };
        let report = check(&xml, &profile).unwrap();
        assert!(
            report
                .validation
                .signers
                .iter()
                .all(|s| s.signature == CheckStatus::Passed),
            "{file}: {report:?}"
        );
        assert!(
            report
                .signatures()
                .iter()
                .all(|s| s.references().iter().all(|r| r.digest_matches))
        );
    }
}

#[test]
fn inclusive_prefix_list_hashes_exact_independent_canonical_bytes() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use der::Encode;
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let ds = "http://www.w3.org/2000/09/xmldsig#";
    let exc = oncl_xml::C14n::Exclusive.uri();
    let digest = STANDARD.encode(
        oncl_pki::key::HashAlg::Sha256
            .digest(b"<a xmlns=\"urn:r\" xmlns:p=\"urn:p\" Id=\"x\">text</a>"),
    );
    // These canonical bytes are a fixed independent input to RSA, not output
    // from the canonicalizer being tested.
    let info = format!(
        "<ds:SignedInfo xmlns=\"urn:r\" xmlns:ds=\"{ds}\" xmlns:p=\"urn:p\"><ds:CanonicalizationMethod Algorithm=\"{exc}\"><ec:InclusiveNamespaces xmlns:ec=\"{exc}\" PrefixList=\"#default p\"></ec:InclusiveNamespaces></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#x\"><ds:Transforms><ds:Transform Algorithm=\"{exc}\"><ec:InclusiveNamespaces xmlns:ec=\"{exc}\" PrefixList=\"#default p\"></ec:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let value = STANDARD.encode(
        key.key
            .sign(oncl_pki::key::SigAlg::RsaSha256, info.as_bytes())
            .unwrap(),
    );
    let certificate = STANDARD.encode(key.cert.to_der().unwrap());
    let xml = format!(
        "<r xmlns=\"urn:r\" xmlns:p=\"urn:p\"><a Id=\"x\">text</a><ds:Signature xmlns:ds=\"{ds}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></r>"
    );
    let report = check(xml.as_bytes(), &XmlVerifyProfile::default()).unwrap();
    assert_eq!(
        report.validation.signers[0].signature,
        CheckStatus::Passed,
        "{report:?}"
    );
    assert!(report.signatures()[0].references()[0].digest_matches);
    let excessive = xml.replace(
        "PrefixList=\"#default p\"",
        &format!("PrefixList=\"{}\"", "p ".repeat(129)),
    );
    assert!(matches!(
        check(excessive.as_bytes(), &XmlVerifyProfile::default()),
        Err(oncl_xml::XmlSourceError::Processing(
            ProcessingError::MetadataLimit
        ))
    ));
}

#[test]
fn duplicate_key_info_and_certificate_containers_reject_wrapping() {
    let xml = String::from_utf8(signed()).unwrap();
    for (from, to) in [
        ("<ds:KeyInfo>", "<ds:KeyInfo></ds:KeyInfo><ds:KeyInfo>"),
        ("<ds:X509Data>", "<ds:X509Data></ds:X509Data><ds:X509Data>"),
    ] {
        let wrapped = xml.replacen(from, to, 1);
        assert_ne!(wrapped, xml);
        assert!(
            check(wrapped.as_bytes(), &XmlVerifyProfile::default()).is_err(),
            "{from}"
        );
    }
}

#[test]
fn scoped_signer_facts_bind_the_real_certificate_and_signed_info() {
    use der::Encode;
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let expected = oncl_pki::key::HashAlg::Sha256.digest(&key.cert.to_der().unwrap());
    let report = check(&signed(), &XmlVerifyProfile::default()).unwrap();
    for signer in report.signatures() {
        assert_eq!(signer.algorithm, oncl_pki::key::SigAlg::RsaSha256);
        assert_eq!(signer.certificate_sha256.as_slice(), expected);
        assert!(signer.signature.offset < signer.signed_info.offset);
        assert!(signer.signature.end().unwrap() >= signer.signature_value.end().unwrap());
    }
}

#[test]
fn manifest_references_verify_actual_targets_not_only_manifest_bytes() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use der::Encode;
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let ds = "http://www.w3.org/2000/09/xmldsig#";
    let canonical = oncl_xml::C14n::Inclusive.uri();
    let sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    for correct in [false, true] {
        let digest = STANDARD.encode(oncl_pki::key::HashAlg::Sha256.digest(if correct {
            b"<a Id=\"data\">payload</a>"
        } else {
            b"different payload"
        }));
        let manifest = format!(
            "<ds:Manifest xmlns:ds=\"{ds}\" Id=\"manifest\"><ds:Reference URI=\"#data\"><ds:DigestMethod Algorithm=\"{sha256}\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest>"
        );
        let digest = STANDARD.encode(oncl_pki::key::HashAlg::Sha256.digest(manifest.as_bytes()));
        let info = format!(
            "<ds:SignedInfo xmlns:ds=\"{ds}\"><ds:CanonicalizationMethod Algorithm=\"{canonical}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference Type=\"{ds}Manifest\" URI=\"#manifest\"><ds:DigestMethod Algorithm=\"{sha256}\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let value = STANDARD.encode(
            key.key
                .sign(oncl_pki::key::SigAlg::RsaSha256, info.as_bytes())
                .unwrap(),
        );
        let certificate = STANDARD.encode(key.cert.to_der().unwrap());
        let xml = format!(
            "<r><a Id=\"data\">payload</a>{manifest}<ds:Signature xmlns:ds=\"{ds}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></r>"
        );
        let report = check(xml.as_bytes(), &XmlVerifyProfile::default()).unwrap();
        assert_eq!(
            report.validation.signers[0].signature,
            if correct {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            "{report:?}"
        );
        assert_eq!(report.signatures()[0].references().len(), 2);
        if correct {
            let limited = XmlVerifyProfile {
                max_references: 1,
                ..XmlVerifyProfile::default()
            };
            assert!(check(xml.as_bytes(), &limited).is_err());
            let limited = XmlVerifyProfile {
                max_manifest_depth: 0,
                ..XmlVerifyProfile::default()
            };
            assert!(check(xml.as_bytes(), &limited).is_err());
            let cycle = xml.replacen(
                "<ds:Reference URI=\"#data\">",
                &format!("<ds:Reference Type=\"{ds}Manifest\" URI=\"#manifest\">"),
                1,
            );
            assert!(check(cycle.as_bytes(), &XmlVerifyProfile::default()).is_err());
        }
    }
}

#[test]
fn late_verification_cancellation_retains_intake_and_cleans_owned_scratch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counting {
        size: u64,
        calls: Arc<AtomicUsize>,
        limit: usize,
    }
    impl OperationControl for Counting {
        fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
            if progress.bytes_in == self.size
                && self.calls.fetch_add(1, Ordering::Relaxed) >= self.limit
            {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let xml = signed();
    let limits = ResourceLimits {
        output_bytes: 0,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let owned = std::fs::read_dir(parent.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let anchors = CaSet::new(vec![]);
    let ctx = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut scope = budget
        .begin(
            limits.clone(),
            Arc::new(Counting {
                size: xml.len() as u64,
                calls: calls.clone(),
                limit: usize::MAX,
            }),
        )
        .unwrap();
    let report = verify_source(
        Source::sequential(&mut Cursor::new(&xml), None),
        &XmlVerifyProfile::default(),
        &store,
        &ctx,
        &NetworkPolicy::deny_all(),
        &mut scope,
    )
    .unwrap();
    drop(scope);
    assert!(budget.begin(limits.clone(), Arc::new(Control)).is_err());
    let oncl_xml::XmlVerification { validation, facts } = report;
    drop(validation);
    assert!(budget.begin(limits.clone(), Arc::new(Control)).is_err());
    drop(facts);
    let limit = calls.load(Ordering::Relaxed) * 3 / 4;
    assert!(limit > 10);
    let mut scope = budget
        .begin(
            limits.clone(),
            Arc::new(Counting {
                size: xml.len() as u64,
                calls: Arc::new(AtomicUsize::new(0)),
                limit,
            }),
        )
        .unwrap();
    let result = verify_source(
        Source::sequential(&mut Cursor::new(&xml), None),
        &XmlVerifyProfile::default(),
        &store,
        &ctx,
        &NetworkPolicy::deny_all(),
        &mut scope,
    );
    assert!(matches!(
        result,
        Err(oncl_xml::XmlSourceError::Processing(
            ProcessingError::Cancelled
        )) | Err(oncl_xml::XmlSourceError::Evidence(
            oncl_pki::evidence::EvidenceError::Processing(ProcessingError::Cancelled)
        ))
    ));
    assert_eq!(scope.progress().bytes_in, xml.len() as u64);
    assert_eq!(std::fs::read_dir(&owned).unwrap().count(), 0);
    assert!(budget.begin(limits.clone(), Arc::new(Control)).is_err());
    drop(scope);
    assert!(budget.begin(limits, Arc::new(Control)).is_ok());
}

#[test]
fn supported_algorithm_uris_do_not_silently_ignore_unsupported_parameters() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use der::Encode;
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let ds = "http://www.w3.org/2000/09/xmldsig#";
    let canonical = oncl_xml::C14n::Inclusive.uri();
    let digest = STANDARD.encode(oncl_pki::key::HashAlg::Sha256.digest(b"<a Id=\"x\">text</a>"));
    for signature_parameters in [true, false] {
        let unsupported = "<ds:UnknownParameters></ds:UnknownParameters>";
        let (signature_params, digest_params) = if signature_parameters {
            (unsupported, "")
        } else {
            ("", unsupported)
        };
        let info = format!(
            "<ds:SignedInfo xmlns:ds=\"{ds}\"><ds:CanonicalizationMethod Algorithm=\"{canonical}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\">{signature_params}</ds:SignatureMethod><ds:Reference URI=\"#x\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\">{digest_params}</ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let value = STANDARD.encode(
            key.key
                .sign(oncl_pki::key::SigAlg::RsaSha256, info.as_bytes())
                .unwrap(),
        );
        let certificate = STANDARD.encode(key.cert.to_der().unwrap());
        let xml = format!(
            "<r><a Id=\"x\">text</a><ds:Signature xmlns:ds=\"{ds}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></r>"
        );
        assert!(
            check(xml.as_bytes(), &XmlVerifyProfile::default()).is_err(),
            "signature_parameters={signature_parameters}"
        );
    }
}

#[test]
fn recognized_unbound_or_unsupported_timestamp_evidence_is_not_ignored() {
    let xml = String::from_utf8(signed()).unwrap();
    for evidence in [
        "<x:ArchiveTimeStamp xmlns:x='http://uri.etsi.org/01903/v1.4.1#'>invalid proof</x:ArchiveTimeStamp>",
        "<x:EncapsulatedTimeStamp xmlns:x='http://uri.etsi.org/01903/v1.3.2#'>invalid proof</x:EncapsulatedTimeStamp>",
    ] {
        let changed = xml.replacen(
            "</ds:Signature>",
            &format!("<ds:Object>{evidence}</ds:Object></ds:Signature>"),
            1,
        );
        assert!(check(changed.as_bytes(), &XmlVerifyProfile::default()).is_err());
    }
}

#[test]
fn invalid_xml_limits_fail_before_arithmetic_allocation_or_source_io() {
    struct MustNotRead;
    impl std::io::Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("invalid profile must fail before source I/O")
        }
    }
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let anchors = CaSet::new(vec![]);
    let ctx = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let profile = XmlVerifyProfile {
        xml: oncl_xml::XmlLimits {
            max_namespace_bytes: usize::MAX,
            ..oncl_xml::XmlLimits::default()
        },
        ..XmlVerifyProfile::default()
    };
    assert!(matches!(
        verify_source(
            Source::sequential(&mut MustNotRead, None),
            &profile,
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut scope
        ),
        Err(oncl_xml::XmlSourceError::Processing(
            ProcessingError::InvalidLimits
        ))
    ));
}

#[test]
fn xpointer_location_must_not_silently_choose_a_different_or_first_body() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use der::Encode;
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let ds = "http://www.w3.org/2000/09/xmldsig#";
    let canonical = oncl_xml::C14n::Inclusive.uri();
    let digest =
        STANDARD.encode(oncl_pki::key::HashAlg::Sha256.digest(b"<a Id=\"first\">signed first</a>"));
    let info = format!(
        "<ds:SignedInfo xmlns:ds=\"{ds}\"><ds:CanonicalizationMethod Algorithm=\"{canonical}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#xpointer(/r/a)\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let value = STANDARD.encode(
        key.key
            .sign(oncl_pki::key::SigAlg::RsaSha256, info.as_bytes())
            .unwrap(),
    );
    let certificate = STANDARD.encode(key.cert.to_der().unwrap());
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{ds}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"
    );
    let unique = format!("<r><a Id=\"first\">signed first</a>{signature}</r>");
    assert_eq!(
        check(unique.as_bytes(), &XmlVerifyProfile::default())
            .unwrap()
            .validation
            .signers[0]
            .signature,
        CheckStatus::Passed
    );
    let wrapped = format!(
        "<r><a Id=\"first\">signed first</a><a Id=\"second\">unsigned second</a>{signature}</r>"
    );
    assert!(check(wrapped.as_bytes(), &XmlVerifyProfile::default()).is_err());
}

#[test]
fn canonical_signed_info_metadata_is_bounded_after_xml_attribute_inheritance() {
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let xml = format!("<r xml:lang='{}'>covered</r>", "x".repeat(1024 * 1024));
    let signed = oncl_xml::sign_enveloped(xml.as_bytes(), &key.key, &key.cert).unwrap();
    assert!(matches!(
        check(&signed, &XmlVerifyProfile::default()),
        Err(oncl_xml::XmlSourceError::Processing(
            ProcessingError::MetadataLimit
        ))
    ));
}

#[test]
fn legacy_enveloped_object_reference_keeps_existing_protocol_bytes() {
    use oncl_xml::{Placement, SigningTimeObject, XmlSignSpec};
    let fixture = synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let spec = XmlSignSpec {
        placement: Placement::FirstChildOfDocument,
        signature_id: Some("sig"),
        signing_time_object: Some(SigningTimeObject {
            property_id: "time",
            target_ref: true,
            text: "2026-11-03",
        }),
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = oncl_xml::sign_spec(
        b"<r xmlns='urn:r'><a>payload</a></r>",
        &spec,
        &key.key,
        &key.cert,
    )
    .unwrap();
    let legacy = XmlVerifyProfile {
        canonicalization: oncl_xml::C14nProfile::KalkanLegacy,
        ..XmlVerifyProfile::default()
    };
    let report = check(&signed, &legacy).unwrap();
    assert_eq!(
        report.validation.signers[0].signature,
        CheckStatus::Passed,
        "{report:?}"
    );
    assert_eq!(
        check(&signed, &XmlVerifyProfile::default())
            .unwrap()
            .validation
            .signers[0]
            .signature,
        CheckStatus::Failed
    );
}
