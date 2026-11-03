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

/// Real public Core verification with a substantive large signed reference.
/// Its expected digest comes from independently emitted canonical record
/// literals and real fixture signatures, not the canonicalizer under test.
/// This fixture constructor is not a large-document SDK signing operation.
pub(super) fn run_streaming(out: &Path) -> Result<(), Box<dyn Error>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use der::Encode;
    use oncl_core::{
        Action, Engine, EngineServices, ExecutionGrant, OperationPolicy, ValidationServices,
        VerifyRequest,
    };
    use oncl_pki::{
        http::{HttpError, HttpReply, HttpRequest, HttpTransport},
        io::{Source, TemporaryStore},
        pkix::CaSet,
        resource::{ResourceLimits, SharedBudget},
        validation::{CheckStatus, NetworkPolicy},
    };
    use std::{
        fmt::Write as _,
        io::{BufWriter, Seek, SeekFrom, Write},
        sync::Arc,
    };
    struct Offline;
    impl HttpTransport for Offline {
        fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            Err(HttpError::other("X03 offline host policy"))
        }
    }
    fs::create_dir_all(out)?;
    let scratch = TemporaryStore::new(out)?;
    let global = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(global.clone())?);
    let verify_limits = ResourceLimits {
        output_bytes: 0,
        ..global.clone()
    };
    let validation = ValidationServices::new(
        CaSet::new(vec![
            oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa"))?,
            oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-gost2015"))?,
        ]),
        vec![],
        Arc::new(Offline),
        NetworkPolicy::deny_all(),
        Arc::new(|| {
            time::OffsetDateTime::from_unix_timestamp(1793707200).expect("fixed probe clock")
        }),
    );
    let engine = Engine::new(
        EngineServices::hash_only(verify_limits)
            .with_shared_budget(budget.clone())
            .with_validation(validation)
            .with_temporary_store(scratch.clone()),
    )?;
    let load = |name: &str| -> Result<pkcs12::KeyEntry, Box<dyn Error>> {
        let fixture = synthetic(name);
        pkcs12::load(&read(&fixture.path), &fixture.password)?
            .pop()
            .ok_or_else(|| io::Error::other("empty public synthetic signing fixture").into())
    };
    let near = load("user-rsa-sign")?;
    let far = load("user-gost2015-sign")?;
    let near_only=oncl_xml::sign_element(
        b"<root><near Id='near'>near-covered</near><far Id='far'><records>RECORDS</records>far-covered</far><uncovered>outside</uncovered></root>",
        "/root/near",None,&near.key,&near.cert,
    )?;
    let bounded = oncl_xml::sign_element(&near_only, "/root/far", None, &far.key, &far.cert)?;
    fs::write(out.join("bounded-two-signers.xml"), &bounded)?;
    let text = std::str::from_utf8(&bounded)?;
    fs::write(
        out.join("oracle-covered-mutated.xml"),
        text.replacen("near-covered", "NEAR-covered", 1),
    )?;
    fs::write(
        out.join("oracle-uncovered-mutated.xml"),
        text.replacen(">outside<", ">OUTSIDE<", 1),
    )?;
    let near_text = std::str::from_utf8(&near_only)?;
    let marker = near_text
        .find(">RECORDS<")
        .ok_or("record insertion marker")?
        + 1;
    let (prefix, suffix) = (&near_only[..marker], &near_only[marker + "RECORDS".len()..]);
    let source = out.join("source-two-signers.xml");
    let mut file = BufWriter::with_capacity(262144, fs::File::create(&source)?);
    file.write_all(prefix)?;
    let mut record_count = 0u64;
    let mut record_bytes = 0u64;
    // More than the old 64-MiB DOM input limit, made of unique actual records.
    // Independent fixture construction: emitted records are canonical literals.
    // No call to the canonicalizer under test computes this expected digest.
    let mut far_hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Streebog512);
    far_hash.update(b"<far Id=\"far\"><records>");
    while record_bytes < 65 * 1024 * 1024 {
        let mut record = String::with_capacity(32768);
        write!(
            &mut record,
            "<record category=\"public\" sequence=\"{record_count}\"><values>"
        )?;
        for item in 0..256u64 {
            write!(
                &mut record,
                "Құжат {record_count}/{item}: amount={} units={} status=reviewed &amp; retained; ",
                record_count * 257 + item,
                (item + 1) * 13
            )?;
        }
        record.push_str("</values></record>");
        file.write_all(record.as_bytes())?;
        far_hash.update(record.as_bytes());
        record_bytes += record.len() as u64;
        record_count += 1;
    }
    far_hash.update(b"</records>far-covered</far>");
    let digest = STANDARD.encode(far_hash.finish().as_bytes());
    let ds = "http://www.w3.org/2000/09/xmldsig#";
    let signature_algorithm =
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
    let digest_algorithm = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
    let method = C14n::Exclusive.uri();
    let transform = C14n::InclusiveWithComments.uri();
    let info = format!(
        "<ds:SignedInfo xmlns:ds=\"{ds}\"><ds:CanonicalizationMethod Algorithm=\"{method}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"{signature_algorithm}\"></ds:SignatureMethod><ds:Reference URI=\"#far\"><ds:Transforms><ds:Transform Algorithm=\"{transform}\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"{digest_algorithm}\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let value = STANDARD.encode(far.key.sign(SigAlg::Gost2015_512, info.as_bytes())?);
    let certificate = STANDARD.encode(far.cert.to_der()?);
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{ds}\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"
    );
    let suffix =
        std::str::from_utf8(suffix)?.replacen("</root>", &format!("{signature}</root>"), 1);
    file.write_all(suffix.as_bytes())?;
    file.flush()?;
    drop(file);
    let suffix_text = suffix.as_str();
    let far_offset = prefix.len() as u64
        + record_bytes
        + suffix_text
            .find("far-covered")
            .ok_or("far target content")? as u64;
    let uncovered_offset = prefix.len() as u64
        + record_bytes
        + suffix_text.find("outside").ok_or("uncovered content")? as u64;
    let far_mutation = out.join("source-far-mutated.xml");
    fs::copy(&source, &far_mutation)?;
    let mut mutation = fs::OpenOptions::new().write(true).open(&far_mutation)?;
    mutation.seek(SeekFrom::Start(far_offset))?;
    mutation.write_all(b"FAR-covered")?;
    drop(mutation);
    let uncovered_mutation = out.join("source-uncovered-mutated.xml");
    fs::copy(&source, &uncovered_mutation)?;
    let mut mutation = fs::OpenOptions::new()
        .write(true)
        .open(&uncovered_mutation)?;
    mutation.seek(SeekFrom::Start(uncovered_offset))?;
    mutation.write_all(b"OUTSIDE")?;
    drop(mutation);
    let mut summary = format!(
        "case=X03\nsource_bytes={}\nrecords={record_count}\nrecord_bytes={record_bytes}\nfar_content_offset={far_offset}\npolicy=OfflineReport\nprivate_material=none\n",
        fs::metadata(&source)?.len()
    );
    for (name, path, expected) in [
        (
            "baseline",
            &source,
            [CheckStatus::Passed, CheckStatus::Passed],
        ),
        (
            "far-mutated",
            &far_mutation,
            [CheckStatus::Passed, CheckStatus::Failed],
        ),
        (
            "uncovered-mutated",
            &uncovered_mutation,
            [CheckStatus::Passed, CheckStatus::Passed],
        ),
    ] {
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(super::Control),
        )?;
        let mut input = fs::File::open(path)?;
        let report = engine.verify(
            &VerifyRequest::xml(),
            Source::seekable(&mut input, None),
            None,
            &mut ctx,
        )?;
        if report.signers.len() != 2
            || report
                .signers
                .iter()
                .zip(expected)
                .any(|(s, e)| s.signature != e)
        {
            return Err(
                format!("X03 {name} per-signer cryptographic result mismatch: {report:?}").into(),
            );
        }
        let facts = report
            .xml
            .as_ref()
            .ok_or("missing real XML coverage facts")?;
        let large_reference = facts
            .signatures()
            .get(1)
            .and_then(|s| s.references().first())
            .and_then(|r| r.target)
            .ok_or("missing actual large canonical reference")?;
        if large_reference.len <= 64 * 1024 * 1024 {
            return Err(
                "X03 did not verify an actual canonical reference larger than 64 MiB".into(),
            );
        }
        writeln!(
            &mut summary,
            "{name}-large_reference_bytes={}",
            large_reference.len
        )?;
        let mut details = format!(
            "case={name}\nverdict={:?}\npolicy={:?}\nchecked_at={}\n",
            report.verdict, report.policy, report.checked_at
        );
        for (index, (signer, facts)) in report.signers.iter().zip(facts.signatures()).enumerate() {
            writeln!(
                &mut details,
                "signer={index} algorithm={:?} certificate_sha256={:02x?} signature={:?} chain={:?} validity={:?} revocation={:?} timestamp={:?} time_basis={:?} signature_region={:?} signed_info={:?} signature_value={:?} references={:?} reasons={:?}",
                facts.algorithm,
                facts.certificate_sha256,
                signer.signature,
                signer.chain,
                signer.validity,
                signer.revocation,
                signer.timestamp,
                signer.time_basis,
                facts.signature,
                facts.signed_info,
                facts.signature_value,
                facts.references(),
                signer.reasons
            )?;
        }
        fs::write(out.join(format!("X03-{name}-per-signer.txt")), &details)?;
        summary.push_str(&format!(
            "{name}={:?},{:?}; verdict={:?}\n",
            report.signers[0].signature, report.signers[1].signature, report.verdict
        ));
    }
    let duplicate = text.replace("</root>", "<near Id='near'>forged body</near></root>");
    fs::write(out.join("duplicate-target.xml"), &duplicate)?;
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Verify]),
        OperationPolicy::offline_report(),
        Arc::new(super::Control),
    )?;
    if engine
        .verify(
            &VerifyRequest::xml(),
            Source::sequential(&mut io::Cursor::new(duplicate.as_bytes()), None),
            None,
            &mut ctx,
        )
        .is_ok()
    {
        return Err("X03 duplicate target was accepted".into());
    }
    drop(ctx);
    summary.push_str("duplicate-target=rejected\n");
    let denied = text.replace(
        C14n::InclusiveWithComments.uri(),
        "http://www.w3.org/TR/1999/REC-xslt-19991116",
    );
    if denied == text {
        return Err("X03 did not mutate an actual reference transform".into());
    }
    fs::write(out.join("denied-transform.xml"), &denied)?;
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Verify]),
        OperationPolicy::offline_report(),
        Arc::new(super::Control),
    )?;
    if engine
        .verify(
            &VerifyRequest::xml(),
            Source::sequential(&mut io::Cursor::new(denied.as_bytes()), None),
            None,
            &mut ctx,
        )
        .is_ok()
    {
        return Err("X03 unsupported transform was accepted".into());
    }
    drop(ctx);
    summary.push_str("unsupported-transform=rejected\n");
    let oracle="<?xml version='1.0'?><?pre   value?><r xmlns='urn:r' xmlns:p='urn:unused' xml:lang='kk' z='&quot;' a='a&#10;b'><n xmlns=''>Қазақ &amp; XML<![CDATA[<raw>]]><!--inside--></n></r><?post done?><!--outside-->".as_bytes();
    fs::write(out.join("oracle-input.xml"), oracle)?;
    let mut scope = budget.begin(global, Arc::new(super::Control))?;
    let mut document = oncl_xml::XmlDocument::index(
        Source::sequential(&mut io::Cursor::new(oracle), None),
        &oncl_xml::XmlLimits::default(),
        &scratch,
        &mut scope,
    )?;
    for (name, method) in [
        ("inclusive", C14n::Inclusive),
        ("inclusive-comments", C14n::InclusiveWithComments),
        ("exclusive", C14n::Exclusive),
        ("exclusive-comments", C14n::ExclusiveWithComments),
    ] {
        let mut output = fs::File::create(out.join(format!("oracle-{name}.xml")))?;
        document.canonicalize(
            None,
            method,
            oncl_xml::C14nProfile::Standard,
            &mut output,
            &mut scope,
        )?;
    }
    drop(document);
    drop(scope);
    summary.push_str("independent_oracle=run xml_oracle.py on bounded oracle artifacts; no GOST oracle claim\nlarge_dom=not-used\nlarge_signing=not-implemented-or-claimed\n10GiB_RSS_gate=not-run\n");
    fs::write(out.join("X03-report.txt"), &summary)?;
    println!("{summary}");
    Ok(())
}
