//! D2: an Add whose new signature would change bytes an existing signature's reference
//! covers is refused from the existing signatures alone, before any key use. Manifest
//! members are followed exactly as verification follows them.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::Encode;
use oncl_pki::{
    io::{Source, TemporaryStore},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use oncl_testkit::{read, synthetic};
use oncl_xml::{C14nProfile, XmlSignMode, XmlSignProfile, XmlSourceError, sign_source};
use std::{io::Cursor, sync::Arc};

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn key() -> oncl_pki::pkcs12::KeyEntry {
    let f = synthetic("user-rsa-sign");
    oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0)
}
/// A signature whose SignedInfo references a Manifest whose single member is `member_uri`.
/// Digests are not meaningful: the preflight reads structure only.
fn with_manifest(member_uri: &str) -> String {
    let key = key();
    let manifest = format!(
        "<ds:Manifest xmlns:ds=\"{DS}\" Id=\"m\"><ds:Reference URI=\"{member_uri}\"><ds:DigestMethod Algorithm=\"{SHA256}\"/><ds:DigestValue>{0}</ds:DigestValue></ds:Reference></ds:Manifest>",
        STANDARD.encode([0u8; 32])
    );
    let info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference Type=\"{DS}Manifest\" URI=\"#m\"><ds:DigestMethod Algorithm=\"{SHA256}\"/><ds:DigestValue>{0}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        STANDARD.encode(oncl_pki::key::HashAlg::Sha256.digest(manifest.as_bytes()))
    );
    let value = STANDARD.encode(
        key.key
            .sign(oncl_pki::key::SigAlg::RsaSha256, info.as_bytes())
            .unwrap(),
    );
    let certificate = STANDARD.encode(key.cert.to_der().unwrap());
    format!(
        "<r Id=\"root\"><a Id=\"data\">payload</a>{manifest}<ds:Signature xmlns:ds=\"{DS}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></r>"
    )
}
fn add(xml: &str, canonicalization: C14nProfile) -> Result<Vec<u8>, XmlSourceError> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut signer = key();
    let mut output = Vec::new();
    sign_source(
        Source::sequential(&mut Cursor::new(xml.as_bytes().to_vec()), None),
        &XmlSignProfile {
            mode: XmlSignMode::Add,
            target: Some("data"),
            canonicalization,
            ..Default::default()
        },
        &mut signer,
        &store,
        &mut output,
        &mut scope,
    )
    .map(|_| output)
}
fn refused_before_key_use(result: Result<Vec<u8>, XmlSourceError>) -> bool {
    matches!(result, Err(XmlSourceError::Unsupported(m)) if m.starts_with("Add would change"))
}

#[test]
fn a_manifest_member_covering_the_insertion_point_is_refused_before_key_use() {
    // The member covers the whole document element, in which the new signature goes.
    assert!(refused_before_key_use(add(
        &with_manifest("#root"),
        C14nProfile::Standard
    )));
}

#[test]
fn a_manifest_member_elsewhere_still_allows_the_add() {
    let added = add(&with_manifest("#data"), C14nProfile::Standard).expect("add");
    assert_eq!(
        String::from_utf8(added)
            .unwrap()
            .matches("<ds:SignatureValue")
            .count(),
        2
    );
}

#[test]
fn kalkan_legacy_excludes_later_signatures_so_the_add_is_not_refused() {
    // Same covering member, but the legacy canonicalization drops later signatures from
    // the digest, exactly as its verification does: the preflight must not refuse.
    let result = add(&with_manifest("#root"), C14nProfile::KalkanLegacy);
    assert!(!refused_before_key_use(result));
}
