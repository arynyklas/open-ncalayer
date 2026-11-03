use oncl_pki::{
    cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec, TimeForm},
    pkcs12::{self, KeyEntry},
};
use time::macros::datetime;
fn entry(name: &str) -> KeyEntry {
    let fixture = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}
#[test]
fn explicit_leaf_signer_reuses_profiles_without_issuer_algorithm_inheritance() {
    // Break caught: guarded signer inherits certificate-issuer signature algorithm,
    // or extraction loses custom attrs/chain/time/attachment selectors.
    let mut leaf = entry("user-rsa-sign");
    let root = entry("root-gost2015.key");
    let spec_cert = oncl_pki::testing::TestCertSpec::from_cert(&leaf.cert);
    leaf.cert = oncl_pki::testing::issue_cert(&root, spec_cert);
    let mut attrs = AttrSpec::cades(datetime!(2026-11-02 12:00 UTC));
    attrs.signing_time = Some((datetime!(2026-11-02 12:00 UTC), TimeForm::Generalized));
    attrs.extra.push((
        der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4"),
        vec![vec![4, 3, b'a', b'b', b'c']],
    ));
    let spec = SignSpec {
        content: Content::Data(b"real guarded CMS"),
        encapsulate: true,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs,
        certificates: CertSpec::Chain,
    };
    assert!(cms::sign_spec(&leaf, &[], &spec).is_err());
    use oncl_pki::resource::*;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }
    let limits = ResourceLimits::default();
    let budget = std::sync::Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = budget.begin(limits, std::sync::Arc::new(Control)).unwrap();
    let mut metadata = scope.reserve_metadata(0).unwrap();
    let mut memory = scope.reserve_memory(0).unwrap();
    let mut projected = None;
    let mut admission = |plan: cms::CmsAdmission| {
        if plan.metadata_bytes > metadata.bytes() {
            metadata
                .grow(plan.metadata_bytes - metadata.bytes())
                .unwrap();
        }
        if plan.memory_bytes > memory.bytes() {
            memory.grow(plan.memory_bytes - memory.bytes()).unwrap();
        }
        if let Some(size) = plan.output_der_bytes {
            scope.check_output_capacity(size).unwrap();
            projected = Some(size);
        }
        assert_eq!(scope.progress().bytes_out, 0);
        Ok(())
    };
    let der = cms::sign_spec_with_signer(&mut leaf, &[root.cert], &spec, &mut admission).unwrap();
    assert_eq!(projected, Some(der.len() as u64));
    scope.account_output(der.len() as u64).unwrap();
    assert_eq!(scope.progress().bytes_out, der.len() as u64);
    let signatures = cms::verify(&der, None).unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].sig_alg, oncl_pki::key::SigAlg::RsaSha256);
    let mut altered = der.clone();
    let at = altered
        .windows(b"real guarded CMS".len())
        .position(|bytes| bytes == b"real guarded CMS")
        .unwrap();
    altered[at] ^= 1;
    assert!(cms::verify(&altered, None).is_err());
}

#[test]
fn readonly_output_preflight_preserves_counter_overflow_and_cancellation() {
    use oncl_pki::resource::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Control(AtomicBool);
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let limits = ResourceLimits {
        output_bytes: u64::MAX,
        ..ResourceLimits::default()
    };
    let control = Arc::new(Control(AtomicBool::new(false)));
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = budget.begin(limits, control.clone()).unwrap();
    scope.account_output(u64::MAX - 3).unwrap();
    scope.check_output_capacity(3).unwrap();
    assert_eq!(scope.progress().bytes_out, u64::MAX - 3);
    assert!(matches!(
        scope.check_output_capacity(4),
        Err(ProcessingError::OutputLimit)
    ));
    scope.account_output(3).unwrap();
    assert!(matches!(
        scope.check_output_capacity(1),
        Err(ProcessingError::OutputLimit)
    ));
    assert_eq!(scope.progress().bytes_out, u64::MAX);
    control.0.store(true, Ordering::SeqCst);
    assert!(matches!(
        scope.check_output_capacity(0),
        Err(ProcessingError::Cancelled)
    ));
}

#[test]
fn exact_projection_covers_real_rsa_and_both_gost_signature_widths() {
    use oncl_pki::resource::*;
    use std::sync::Arc;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }
    for (name, algorithm) in [
        ("user-rsa-sign", oncl_pki::key::SigAlg::RsaSha256),
        ("user-gost2004-sign", oncl_pki::key::SigAlg::Gost2004),
        ("user-gost2015-sign", oncl_pki::key::SigAlg::Gost2015_512),
    ] {
        let mut key = entry(name);
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let mut guard = scope.reserve_metadata(0).unwrap();
        let mut document = scope.reserve_memory(0).unwrap();
        for length in [127usize, 256, 65_535] {
            let data = vec![b'x'; length];
            let spec = SignSpec {
                content: Content::Data(&data),
                encapsulate: true,
                cosign: CoSign::Never,
                econtent_type: None,
                digest: None,
                attrs: AttrSpec::cades(datetime!(2026-11-02 12:00 UTC)),
                certificates: CertSpec::Signer,
            };
            let mut projected = 0;
            let mut admission = |plan: cms::CmsAdmission| {
                if plan.metadata_bytes > guard.bytes() {
                    guard.grow(plan.metadata_bytes - guard.bytes()).unwrap();
                }
                if plan.memory_bytes > document.bytes() {
                    document.grow(plan.memory_bytes - document.bytes()).unwrap();
                }
                if let Some(size) = plan.output_der_bytes {
                    scope.check_output_capacity(size).unwrap();
                    projected = size;
                }
                Ok(())
            };
            let der = cms::sign_spec_with_signer(&mut key, &[], &spec, &mut admission).unwrap();
            assert_eq!(projected, der.len() as u64);
            assert_eq!(cms::verify(&der, None).unwrap()[0].sig_alg, algorithm);
        }
    }
}
