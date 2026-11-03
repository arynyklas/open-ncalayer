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
    let der = cms::sign_spec_with_signer(&mut leaf, &[root.cert], &spec).unwrap();
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
