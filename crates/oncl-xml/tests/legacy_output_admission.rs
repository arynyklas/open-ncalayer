//! Exact pre-private bounds use the same renderer/output rule, never a fake signature.
use oncl_pki::{
    digest::DigestValue,
    io::{Source, TemporaryStore, XmlSignatureOutput},
    key::{DigestSigner, KeyError, SigAlg},
    resource::*,
};
use oncl_xml::{SigningTimeObject, XmlOutput, XmlSignSpec};
use std::{
    io::Cursor,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct Counted {
    entry: oncl_pki::pkcs12::KeyEntry,
    calls: Arc<AtomicUsize>,
}
impl DigestSigner for Counted {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        &self.entry.cert
    }
    fn algorithm(&self) -> SigAlg {
        DigestSigner::algorithm(&self.entry)
    }
    fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        DigestSigner::sign_digest(&mut self.entry, digest)
    }
}
#[test]
fn actual_rsa_and_gost_output_bounds_fit_exactly_and_reject_one_less_before_use() {
    let xml=b"\xef\xbb\xbf<?xml version='1.0' encoding='UTF-8'?> \r\n<r xmlns:p='urn:p'><p:data Id='x'>protected</p:data><s/></r> \t\r\n";
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let fixture = oncl_testkit::synthetic(name);
        let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
            .unwrap()
            .remove(0);
        for (output, wrapped) in [
            (XmlOutput::AsIs, false),
            (XmlOutput::AsIs, true),
            (
                XmlOutput::Serialize {
                    declaration: false,
                    standalone_no: false,
                    trim: true,
                },
                false,
            ),
            (
                XmlOutput::Serialize {
                    declaration: true,
                    standalone_no: true,
                    trim: false,
                },
                true,
            ),
        ] {
            let mut spec = XmlSignSpec::kalkan(Some("//p:data"), Some("/r/s"));
            spec.namespaces.push(("p", "urn:p"));
            spec.signature_id = Some("sig");
            spec.strip_whitespace = !wrapped;
            spec.base64_line_breaks = Some(wrapped);
            spec.output = output;
            spec.signing_time_object = Some(SigningTimeObject {
                property_id: "time",
                target_ref: true,
                text: "2026-11-02T12:00:00Z",
            });
            let expected = oncl_xml::sign_spec(xml, &spec, &entry.key, &entry.cert).unwrap();
            for fit in [false, true] {
                let limits = ResourceLimits {
                    output_bytes: expected.len() as u64 - u64::from(!fit),
                    ..Default::default()
                };
                let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
                let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
                let directory = tempfile::tempdir().unwrap();
                let store = TemporaryStore::new(directory.path()).unwrap();
                let prepared = oncl_xml::prepare_legacy_source(
                    Source::sequential(&mut Cursor::new(xml), Some(xml.len() as u64)),
                    &spec,
                    &store,
                    &mut scope,
                )
                .unwrap();
                let mut stage = store.stage(&mut scope).unwrap();
                let mut target = XmlSignatureOutput::new(&mut stage, &scope).unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let mut signer = Counted {
                    entry: entry.clone(),
                    calls: calls.clone(),
                };
                let view = scope.shared_view();
                let mut projected = None;
                let mut admit = |bytes| {
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    assert_eq!(view.progress().bytes_out, 0);
                    projected = Some(bytes);
                    view.check_output_capacity(bytes)
                };
                let result =
                    prepared.sign_transaction(&mut signer, &mut target, &mut scope, &mut admit);
                if fit {
                    let summary = result.unwrap();
                    assert_eq!(projected, Some(expected.len() as u64));
                    assert_eq!(summary.bytes_out, expected.len() as u64);
                    target.finish(&scope).unwrap();
                    let mut actual = Vec::new();
                    stage.copy_to(&mut actual).unwrap();
                    assert_eq!(actual.len(), expected.len());
                    assert_eq!(oncl_xml::verify(&actual).unwrap().len(), 1);
                    if name == "user-rsa-sign" {
                        assert_eq!(actual, expected);
                    }
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(scope.progress().bytes_out, expected.len() as u64);
                } else {
                    assert!(result.is_err());
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    assert_eq!(scope.progress().bytes_out, 0);
                }
            }
        }
    }
}
