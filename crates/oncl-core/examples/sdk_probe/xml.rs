//! Real bounded XML smoke; cryptographic verification is not a trust verdict.

use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12;
use oncl_testkit::{read, synthetic};
use oncl_xml::{C14n, canonicalize, sign_enveloped, verify};
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;

pub(super) fn run(out: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(out)?;
    let input = b"<root xmlns=\"urn:oncl:probe\"><data Id=\"d1\">bounded XML</data></root>";
    let canonical = canonicalize(input, C14n::Inclusive, None)?;
    let expected = b"<root xmlns=\"urn:oncl:probe\"><data Id=\"d1\">bounded XML</data></root>";
    if canonical != expected {
        return Err(io::Error::other("unexpected XML canonical bytes").into());
    }
    fs::write(out.join("xml-input.xml"), input)?;
    fs::write(out.join("xml-canonical.xml"), &canonical)?;
    for (name, algorithm) in [
        ("user-rsa-sign", SigAlg::RsaSha256),
        ("user-gost2004-sign", SigAlg::Gost2004),
        ("user-gost2015-sign", SigAlg::Gost2015_512),
    ] {
        let fixture = synthetic(name);
        let mut entries = pkcs12::load(&read(&fixture.path), &fixture.password)?;
        let signer = entries
            .pop()
            .ok_or_else(|| io::Error::other("empty XML smoke key store"))?;
        let signed = sign_enveloped(input, &signer.key, &signer.cert)?;
        let signatures = verify(&signed)?;
        if signatures.len() != 1
            || signatures[0].sig_alg != algorithm
            || signatures[0].cert != signer.cert
        {
            return Err(io::Error::other("unexpected XML cryptographic signer").into());
        }
        let mut tampered = signed.clone();
        let at = tampered
            .windows(b"bounded XML".len())
            .position(|bytes| bytes == b"bounded XML")
            .ok_or_else(|| io::Error::other("XML smoke content missing"))?;
        tampered[at] = b'B';
        if verify(&tampered) != Err(oncl_xml::XmlError::BadDigest) {
            return Err(io::Error::other("tampered XML digest was not rejected").into());
        }
        fs::write(out.join(format!("xml-{name}-signed.xml")), &signed)?;
    }
    Ok(())
}
