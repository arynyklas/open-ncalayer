//! Public P02 artifacts. Synthetic fixture keys stay in memory, never output.
use der::Encode;
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationPolicy, SignRequest, VerifyRequest,
    keys::{
        KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
    },
};
use oncl_pki::{
    io::{Source, TemporaryStore},
    resource::ResourceLimits,
    validation::{CheckStatus, Verdict},
};
use std::{
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex},
};
struct Consent {
    keys: Vec<oncl_core::keys::KeyId>,
    events: Mutex<Vec<KeyUseEvent>>,
}
impl KeyUseGuard for Consent {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, oncl_core::OperationError> {
        if event.action != Action::Sign || !self.keys.contains(&event.key_id) {
            return Err(oncl_core::OperationError::PermissionDenied);
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(
        &self,
        _: KeyUseReceipt,
        outcome: KeyUseOutcome,
    ) -> Result<(), oncl_core::OperationError> {
        if !outcome.succeeded || outcome.applied != oncl_core::keys::AppliedState::Applied {
            return Err(oncl_core::OperationError::AuditFailed);
        }
        Ok(())
    }
}
fn selector(entry: oncl_pki::pkcs12::KeyEntry) -> Result<KeySelector, Box<dyn std::error::Error>> {
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: entry.alias,
            pkcs8_der: entry.key.to_pkcs8_der()?.to_vec(),
            cert_der: Some(entry.cert.to_der()?),
        }],
        &[],
        "P02 synthetic",
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x72),
    )?;
    Ok(KeySelector::inline(bytes, None))
}
fn source() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use lopdf::{Document, Object, Stream, dictionary};
    let mut doc = Document::load_mem(include_bytes!(
        "../../../oncl-pdf/tests/fixtures/external-multipage.pdf"
    ))?;
    // Substantive visible RGB image data, not sparse/padding bytes. The probe's
    // independent writer may use a small heap document; the Engine never does.
    let pixels: Vec<u8> = (0..1024 * 1024 * 3)
        .map(|n| (((n / 3) % 1024) ^ ((n / 3072) * 13) ^ (n % 3 * 71)) as u8)
        .collect();
    let image=doc.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Image","Width"=>1024,"Height"=>1024,"ColorSpace"=>"DeviceRGB","BitsPerComponent"=>8},pixels));
    let extra = doc.add_object(Stream::new(
        lopdf::Dictionary::new(),
        b"q 256 0 0 256 40 200 cm /P02Image Do Q\n".to_vec(),
    ));
    for (_, id) in doc.get_pages() {
        let page = doc.get_object(id)?.as_dict()?.clone();
        let resources = page.get(b"Resources")?.clone();
        let mut resources = match resources {
            Object::Reference(r) => doc.get_object(r)?.as_dict()?.clone(),
            Object::Dictionary(d) => d,
            _ => return Err("unexpected independent page resources".into()),
        };
        resources.set("XObject", dictionary! {"P02Image"=>image});
        let old = page.get(b"Contents")?.clone();
        let mut contents = match old {
            Object::Array(v) => v,
            v => vec![v],
        };
        contents.push(Object::Reference(extra));
        let page = doc.get_object_mut(id)?.as_dict_mut()?;
        page.set("Resources", resources);
        page.set("Contents", Object::Array(contents));
    }
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes)?;
    Ok(bytes)
}
pub fn run(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    let scratch = tempfile::tempdir()?;
    let fixture = super::probe_key_copy("user-rsa-sign", scratch.path())?;
    let first =
        oncl_pki::pkcs12::load(&std::fs::read(&fixture.path)?, &fixture.password)?.remove(0);
    let mut second = oncl_pki::pkcs12::load(
        &oncl_testkit::read(oncl_testkit::fixture("openssl/rsa-modern.p12")),
        "Qwerty12",
    )?
    .remove(0);
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&first.cert);
    spec.public_key = second
        .cert
        .tbs_certificate()
        .subject_public_key_info()
        .clone();
    spec.serial = vec![0x70, 0x02];
    spec.extensions
        .retain(|e| e.extn_id.to_string() != "2.5.29.14");
    second.cert = oncl_pki::testing::issue_cert(&super::fixture_entry("inter-gost2015.key"), spec);
    let first_certificate = first.cert.to_der()?;
    let second_certificate = second.cert.to_der()?;
    if first.cert.tbs_certificate().subject_public_key_info()
        == second.cert.tbs_certificate().subject_public_key_info()
    {
        return Err("P02 requires two actual keys".into());
    }
    let keys = [selector(first)?, selector(second)?];
    let guard = Arc::new(Consent {
        keys: keys.iter().map(KeySelector::key_id).collect(),
        events: Mutex::new(Vec::new()),
    });
    let store = TemporaryStore::new(out)?;
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(Arc::new(KeySources::new()), guard.clone())
            .with_validation(super::probe_validation())
            .with_temporary_store(store.clone()),
    )?;
    let original = source()?;
    if original.len() < 3 * 1024 * 1024 {
        return Err("P02 substantive source too short".into());
    }
    std::fs::write(out.join("source.pdf"), &original)?;
    std::fs::write(out.join("first-cert.der"), first_certificate)?;
    std::fs::write(out.join("second-cert.der"), second_certificate)?;
    let mut previous = original.clone();
    let mut report = String::new();
    for (i, key) in keys.iter().enumerate() {
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(super::Control),
        )?;
        let mut output = store.stage(ctx.resources())?;
        let signed = engine.sign_staged(
            SignRequest::pdf(
                KeyRequest::new(key, Some("P02 synthetic")),
                oncl_pdf::PdfSignProfile::default(),
            ),
            Source::seekable(&mut Cursor::new(&previous), None),
            &mut output,
            &mut ctx,
        )?;
        if signed.bytes_in != previous.len() as u64 || signed.bytes_out != output.len() {
            return Err("P02 I/O accounting mismatch".into());
        }
        let name = if i == 0 {
            "once-signed.pdf"
        } else {
            "twice-signed.pdf"
        };
        output.commit(&out.join(name))?;
        let bytes = std::fs::read(out.join(name))?;
        if !bytes.starts_with(&previous) {
            return Err("P02 original revision changed".into());
        }
        report.push_str(&format!("{name}: {signed:?}\n"));
        drop(signed);
        drop(ctx);
        let mut verify = engine.begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::strict_online(),
            Arc::new(super::Control),
        )?;
        let checked = engine.verify(
            &VerifyRequest::pdf(),
            Source::seekable(&mut Cursor::new(&bytes), None),
            None,
            &mut verify,
        )?;
        if checked.verdict != Verdict::Valid
            || checked.signers.len() != i + 1
            || !checked
                .signers
                .iter()
                .all(|s| s.signature == CheckStatus::Passed)
        {
            return Err("P02 new/old signature verification failed".into());
        }
        report.push_str(&format!("verification={checked:?}\n"));
        previous = bytes;
    }
    let mut tampered = previous.clone();
    let at = tampered
        .windows(18)
        .position(|w| w == b"P02 external page ")
        .ok_or("missing covered external text")?;
    tampered[at] = b'Q';
    std::fs::write(out.join("covered-mutation.pdf"), &tampered)?;
    let mut verify = engine.begin(
        ExecutionGrant::new([Action::Verify]),
        OperationPolicy::strict_online(),
        Arc::new(super::Control),
    )?;
    let negative = engine.verify(
        &VerifyRequest::pdf(),
        Source::seekable(&mut Cursor::new(&tampered), None),
        None,
        &mut verify,
    )?;
    if negative.verdict != Verdict::Invalid
        || !negative
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Failed)
    {
        return Err("P02 covered mutation accepted".into());
    }
    report.push_str(&format!(
        "covered-mutation={negative:?}\nkey-uses={}\n",
        guard.events.lock().unwrap().len()
    ));
    drop(negative);
    drop(verify);
    // An independent minimal unsigned /Info update: old CMS remains intact, but
    // no signature covers the newest revision, and Add must not launder it.
    let parsed = lopdf::Document::load_mem(&previous)?;
    let root = parsed.trailer.get(b"Root")?.as_reference()?;
    let next = parsed
        .max_id
        .checked_add(1)
        .ok_or("probe object id overflow")?;
    let marker = previous
        .windows(9)
        .rposition(|w| w == b"startxref")
        .ok_or("probe startxref")?
        + 9;
    let prev: u64 = std::str::from_utf8(&previous[marker..])?
        .split_whitespace()
        .next()
        .ok_or("probe xref offset")?
        .parse()?;
    let mut later = previous.clone();
    later.push(b'\n');
    let offset = later.len();
    later.extend_from_slice(
        format!("{next} 0 obj\n<< /Title (P02 unsigned later change) >>\nendobj\n").as_bytes(),
    );
    let xref = later.len();
    later.extend_from_slice(format!("xref\n{next} 1\n{offset:010} 00000 n \ntrailer\n<< /Size {} /Root {} {} R /Info {next} 0 R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n",next+1,root.0,root.1).as_bytes());
    std::fs::write(out.join("unsigned-later.pdf"), &later)?;
    let mut verify = engine.begin(
        ExecutionGrant::new([Action::Verify]),
        OperationPolicy::strict_online(),
        Arc::new(super::Control),
    )?;
    let outside = engine.verify(
        &VerifyRequest::pdf(),
        Source::seekable(&mut Cursor::new(&later), None),
        None,
        &mut verify,
    )?;
    if outside.verdict != Verdict::Indeterminate
        || !outside
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
        || !outside
            .pdf
            .as_ref()
            .ok_or("missing revision facts")?
            .signatures
            .iter()
            .all(|s| s.later_changes)
    {
        return Err("P02 unsigned latest revision became Valid".into());
    }
    report.push_str(&format!("unsigned-later={outside:?}\n"));
    drop(outside);
    drop(verify);
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Sign]).with_keys([keys[0].key_id()]),
        OperationPolicy::strict_online(),
        Arc::new(super::Control),
    )?;
    let mut stage = store.stage(ctx.resources())?;
    let error = engine
        .sign_staged(
            SignRequest::pdf(
                KeyRequest::new(&keys[0], Some("P02 synthetic")),
                oncl_pdf::PdfSignProfile::default(),
            ),
            Source::seekable(&mut Cursor::new(&later), None),
            &mut stage,
            &mut ctx,
        )
        .unwrap_err();
    if error.applied_state() != oncl_core::keys::AppliedState::NotApplied
        || stage.copy_to(&mut Vec::new()).is_ok()
    {
        return Err("P02 unsigned-later Add partially succeeded".into());
    }
    report.push_str(&format!("unsigned-later-add={error:?}\n"));
    drop(ctx);
    for (name, ending) in [("bare-eof", b"".as_slice()), ("bare-cr", b"\r".as_slice())] {
        // Separate low-level synthetic fixture generation: genuinely sign these EOF
        // bytes with the owned fixture key; do not strip an already signed newline.
        let mut fixture_key =
            oncl_pki::pkcs12::load(&std::fs::read(&fixture.path)?, &fixture.password)?.remove(0);
        let mut fixture_ctx = engine.begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(super::Control),
        )?;
        let before = independent_eof_signature(
            &original,
            ending,
            &store,
            &mut fixture_key,
            fixture_ctx.resources(),
        )?;
        drop(fixture_ctx);
        std::fs::write(out.join(format!("{name}-before.pdf")), &before)?;
        let mut verify = engine.begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::strict_online(),
            Arc::new(super::Control),
        )?;
        let checked = engine.verify(
            &VerifyRequest::pdf(),
            Source::seekable(&mut Cursor::new(&before), None),
            None,
            &mut verify,
        )?;
        if checked.verdict != Verdict::Valid || checked.signers.len() != 1 {
            return Err("P02 bare EOF producer signature invalid before Add".into());
        }
        report.push_str(&format!("{name}-before={checked:?}\n"));
        drop(checked);
        drop(verify);
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Sign]).with_keys([keys[1].key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(super::Control),
        )?;
        let mut stage = store.stage(ctx.resources())?;
        let signed = engine.sign_staged(
            SignRequest::pdf(
                KeyRequest::new(&keys[1], Some("P02 synthetic")),
                oncl_pdf::PdfSignProfile::default(),
            ),
            Source::seekable(&mut Cursor::new(&before), None),
            &mut stage,
            &mut ctx,
        )?;
        let path = out.join(format!("{name}-after.pdf"));
        stage.commit(&path)?;
        drop(signed);
        drop(ctx);
        let after = std::fs::read(path)?;
        if !after.starts_with(&before) {
            return Err("P02 bare EOF prefix changed".into());
        }
        let mut verify = engine.begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::strict_online(),
            Arc::new(super::Control),
        )?;
        let checked = engine.verify(
            &VerifyRequest::pdf(),
            Source::seekable(&mut Cursor::new(&after), None),
            None,
            &mut verify,
        )?;
        let old = &checked.pdf.as_ref().ok_or("missing EOF facts")?.signatures[0];
        if checked.verdict != Verdict::Valid
            || checked.signers.len() != 2
            || old.revision_end != before.len() as u64
            || old.parser_revision_end != old.revision_end + 1
            || old.endpoint_scope == oncl_pdf::PdfEndpointScope::CurrentExtent
        {
            return Err("P02 historical EOF endpoint facts or signatures invalid".into());
        }
        report.push_str(&format!("{name}-after={checked:?}\n"));
    }
    if guard.events.lock().unwrap().len() != 4 {
        return Err("P02 unexpected Engine key applications".into());
    }
    report.push_str(
        "Engine key uses=4 (main two plus two EOF Adds); low-level synthetic EOF fixture uses=2\n",
    );
    std::fs::write(out.join("p02-results.txt"), &report)?;
    println!(
        "case=P02 source_bytes={} two_actual_rsa_keys=2 signatures=2 prefix=unchanged all_signatures=Valid covered_mutation=Invalid private_material=none\n{report}",
        original.len()
    );
    Ok(())
}

fn independent_eof_signature(
    input: &[u8],
    ending: &[u8],
    store: &TemporaryStore,
    key: &mut dyn oncl_pki::key::DigestSigner,
    scope: &mut oncl_pki::resource::ResourceScope,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use oncl_pki::io::PdfSignatureOutput;
    let parsed = lopdf::Document::load_mem(input)?;
    let root = parsed.trailer.get(b"Root")?.as_reference()?;
    let pages = parsed
        .get_object(root)?
        .as_dict()?
        .get(b"Pages")?
        .as_reference()?;
    let form = parsed.max_id + 1;
    let field = form + 1;
    let sig = form + 2;
    let marker = input
        .windows(9)
        .rposition(|w| w == b"startxref")
        .ok_or("fixture startxref")?
        + 9;
    let prev: u64 = std::str::from_utf8(&input[marker..])?
        .split_whitespace()
        .next()
        .ok_or("fixture xref")?
        .parse()?;
    let mut stage = store.stage(scope)?;
    let mut output = PdfSignatureOutput::new(&mut stage, scope)?;
    output.append(input)?;
    output.append(b"\n")?;
    let mut offsets = std::collections::BTreeMap::new();
    for (id, generation, body) in [
        (
            root.0,
            root.1,
            format!(
                "<< /Type /Catalog /Pages {} {} R /AcroForm {form} 0 R >>",
                pages.0, pages.1
            ),
        ),
        (form, 0, format!("<< /Fields [{field} 0 R] /SigFlags 3 >>")),
        (
            field,
            0,
            format!("<< /FT /Sig /T (IndependentEOF) /V {sig} 0 R >>"),
        ),
    ] {
        offsets.insert((id, generation), output.len());
        output.append(format!("{id} {generation} obj\n{body}\nendobj\n").as_bytes())?;
    }
    offsets.insert((sig, 0), output.len());
    output.append(
        format!(
            "{sig} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached"
        )
        .as_bytes(),
    )?;
    output.reserve_contents(16384)?;
    output.append(b" >>\nendobj\n")?;
    let xref = output.len();
    output.append(b"xref\n")?;
    for ((id, generation), offset) in offsets {
        output.append(format!("{id} 1\n{offset:010} {generation:05} n \n").as_bytes())?;
    }
    output.append(
        format!(
            "trailer\n<< /Size {} /Root {} {} R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF",
            sig + 1,
            root.0,
            root.1
        )
        .as_bytes(),
    )?;
    output.append(ending)?;
    output.finish(
        key,
        &oncl_pki::cms::stream::CmsSignServices::new(None, Some(store)),
        scope,
    )?;
    let mut bytes = Vec::new();
    stage.copy_to(&mut bytes)?;
    Ok(bytes)
}
