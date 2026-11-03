//! Actual crypto and lexical-preservation controls for the source signer.
use oncl_pki::{
    io::{Source, TemporaryStore},
    key::{DigestSigner, SigAlg},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use oncl_testkit::{read, synthetic};
use oncl_xml::{XmlSignMode, XmlSignProfile, sign_source};
use std::{io::Cursor, sync::Arc};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn entry() -> oncl_pki::pkcs12::KeyEntry {
    let f = synthetic("user-rsa-sign");
    oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn sign(xml: &[u8], mode: XmlSignMode) -> Vec<u8> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut signer = entry();
    let mut output = Vec::new();
    let profile = XmlSignProfile {
        target: Some("payload"),
        parent: Some("signatures"),
        mode,
        ..Default::default()
    };
    sign_source(
        Source::sequential(&mut Cursor::new(xml), None),
        &profile,
        &mut signer,
        &store,
        &mut output,
        &mut scope,
    )
    .unwrap();
    output
}
#[test]
fn preserves_unsigned_bytes_and_target() {
    let xml = "<?xml version='1.0'?>\r\n<r xmlns:p='urn:p' xml:lang='kk'><p:data Id='payload' a='&quot;'>қ&amp;т</p:data><s Id='signatures'></s></r>\r\n";
    let signed = sign(xml.as_bytes(), XmlSignMode::Create);
    let marker = xml.find("</s>").unwrap();
    assert_eq!(&signed[..marker], &xml.as_bytes()[..marker]);
    assert!(signed.ends_with(&xml.as_bytes()[marker..]));
    let checked = oncl_xml::verify(&signed).unwrap();
    assert_eq!(checked.len(), 1);
    assert_eq!(checked[0].sig_alg, SigAlg::RsaSha256);
    let tampered = String::from_utf8(signed)
        .unwrap()
        .replace("қ&amp;т", "қ&amp;у");
    assert!(oncl_xml::verify(tampered.as_bytes()).is_err());
}
#[test]
fn add_signature_keeps_prior_reference() {
    let xml = b"<r><data Id='payload'>protected</data><s Id='signatures'/></r>";
    let first = sign(xml, XmlSignMode::Create);
    let second = sign(&first, XmlSignMode::Add);
    let checks = oncl_xml::verify(&second).unwrap();
    assert_eq!(checks.len(), 2);
    let doc = roxmltree::Document::parse(std::str::from_utf8(&second).unwrap()).unwrap();
    let values: Vec<_> = doc
        .descendants()
        .filter(|n| n.tag_name().name() == "SignatureValue")
        .map(|n| n.text().unwrap())
        .collect();
    let original = roxmltree::Document::parse(std::str::from_utf8(&first).unwrap()).unwrap();
    assert_eq!(
        values[0],
        original
            .descendants()
            .find(|n| n.tag_name().name() == "SignatureValue")
            .unwrap()
            .text()
            .unwrap()
    );
    assert!(
        std::str::from_utf8(&second)
            .unwrap()
            .matches("URI=\"#payload\"")
            .count()
            == 2
    );
}
#[test]
fn create_rejects_existing_signature_before_private_use() {
    struct Count {
        inner: oncl_pki::pkcs12::KeyEntry,
        uses: usize,
    }
    impl DigestSigner for Count {
        fn certificate(&self) -> &oncl_pki::cert::Certificate {
            self.inner.certificate()
        }
        fn algorithm(&self) -> SigAlg {
            self.inner.algorithm()
        }
        fn sign_digest(
            &mut self,
            d: &oncl_pki::digest::DigestValue,
        ) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
            self.uses += 1;
            self.inner.sign_digest(d)
        }
    }
    let first = sign(
        b"<r><data Id='payload'/><s Id='signatures'/></r>",
        XmlSignMode::Create,
    );
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut signer = Count {
        inner: entry(),
        uses: 0,
    };
    let mut out = Vec::new();
    assert!(
        sign_source(
            Source::sequential(&mut Cursor::new(first), None),
            &XmlSignProfile {
                target: Some("payload"),
                parent: Some("signatures"),
                ..Default::default()
            },
            &mut signer,
            &store,
            &mut out,
            &mut scope
        )
        .is_err()
    );
    assert_eq!(signer.uses, 0);
    assert!(out.is_empty());
}

#[test]
fn explicit_output_layout_is_common_legacy_bytes() {
    let xml=b"\xef\xbb\xbf<?xml version='1.0'?>\r\n <r xmlns='urn:r' xml:lang='kk'><a>protected</a></r>\n ";
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut signer = entry();
    for strip in [false, true] {
        let output = oncl_xml::XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim: true,
        };
        let profile = XmlSignProfile {
            reference_c14n: oncl_xml::C14n::InclusiveWithComments,
            signed_info_c14n: oncl_xml::C14n::Inclusive,
            canonicalization: oncl_xml::C14nProfile::KalkanLegacy,
            output,
            strip_whitespace: strip,
            base64_line_breaks: None,
            ..Default::default()
        };
        let mut actual = Vec::new();
        sign_source(
            Source::sequential(&mut Cursor::new(xml), None),
            &profile,
            &mut signer,
            &store,
            &mut actual,
            &mut scope,
        )
        .unwrap();
        let expected = oncl_xml::sign_spec(
            xml,
            &oncl_xml::XmlSignSpec {
                output,
                strip_whitespace: strip,
                ..oncl_xml::XmlSignSpec::kalkan(None, None)
            },
            &signer.key,
            &signer.cert,
        )
        .unwrap();
        assert_eq!(
            actual, expected,
            "the streaming adapter must not invent another wire layout"
        );
    }
}

#[test]
fn guarded_legacy_spec_keeps_exact_wire_without_a_raw_private_key_parameter() {
    let xml =
        "<r xmlns:p='urn:p' xml:lang='kk'><p:data Id='payload'>Қ&amp;т</p:data><s/></r>".as_bytes();
    let mut spec = oncl_xml::XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
    spec.namespaces = vec![("p", "urn:p")];
    spec.signature_id = Some("S0");
    spec.signing_time_object = Some(oncl_xml::SigningTimeObject {
        property_id: "st0",
        target_ref: true,
        text: "2026-11-02T12:00:00Z",
    });
    spec.strip_whitespace = false;
    spec.base64_line_breaks = Some(true);
    spec.output = oncl_xml::XmlOutput::Serialize {
        declaration: true,
        standalone_no: true,
        trim: true,
    };
    let mut signer = entry();
    let expected = oncl_xml::sign_spec(xml, &spec, &signer.key, &signer.cert).unwrap();
    let cap = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut scope = budget.begin(cap, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut actual = Vec::new();
    oncl_xml::sign_spec_source(
        Source::sequential(&mut Cursor::new(xml), Some(xml.len() as u64)),
        &spec,
        &mut signer,
        &store,
        &mut actual,
        &mut scope,
    )
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(scope.progress().bytes_in, xml.len() as u64);
    assert_eq!(scope.progress().bytes_out, actual.len() as u64);
    assert_eq!(oncl_xml::verify(&actual).unwrap().len(), 1);
}
