use oncl_pdf::{PdfDocument, PdfLimits, PdfSignProfile, sign_source};
use oncl_pki::{
    cms,
    cms::stream::CmsSignServices,
    io::{Source, TemporaryStore},
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{io::Cursor, sync::Arc};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope() -> ResourceScope {
    let l = ResourceLimits::default();
    Arc::new(SharedBudget::new(l.clone()).unwrap())
        .begin(l, Arc::new(Control))
        .unwrap()
}
fn unsigned() -> Vec<u8> {
    // An independent PDF writer, not the signing implementation.
    use lopdf::{Document, Object, dictionary};
    let mut d = Document::with_version("1.7");
    let pages = d.new_object_id();
    let page=d.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![0.into(),0.into(),612.into(),792.into()]});
    d.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}.into(),
    );
    let root = d.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    d.trailer.set("Root", root);
    let mut v = Vec::new();
    d.save_to(&mut v).unwrap();
    v
}
fn signed(input: &[u8], reservation: usize) -> Result<Vec<u8>, oncl_pdf::PdfError> {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope();
    let f = oncl_testkit::synthetic("user-rsa-sign");
    let mut key = oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0);
    let mut output = store.stage(&mut scope).unwrap();
    sign_source(
        Source::seekable(&mut Cursor::new(input), None),
        &PdfSignProfile::new(reservation).unwrap(),
        &mut key,
        &CmsSignServices::new(None, Some(&store)),
        &mut output,
        &scope,
    )?;
    let mut result = Vec::new();
    output.copy_to(&mut result).unwrap();
    Ok(result)
}
#[test]
fn prior_revision_untouched() {
    use oncl_pki::{
        crl::MockCrl,
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        pkix::CaSet,
        validation::{CheckStatus, ValidationContext, ValidationPolicy, Verdict},
    };
    let now = time::Date::from_calendar_date(2026, time::Month::November, 2)
        .unwrap()
        .with_hms(12, 0, 0)
        .unwrap()
        .assume_utc();
    let root = entry("root-gost2015.key");
    let inter = entry("inter-gost2015.key");
    let anchors = CaSet::new(vec![root.cert.clone()]);
    let intermediates = vec![inter.cert.clone()];
    let ocsp: Arc<dyn HttpTransport> =
        Arc::new(MockOcsp::new(entry("ocsp-gost2015")).with_now(now));
    let root_crl: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(root)
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::HOUR)),
    );
    let inter_crl: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(inter)
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::HOUR)),
    );
    let http = RouteTransport::new(vec![
        ("http://ocsp.synthetic.test".into(), ocsp),
        (
            "http://crl.synthetic.test/root-gost2015.crl".into(),
            root_crl,
        ),
        (
            "http://crl.synthetic.test/inter-gost2015.crl".into(),
            inter_crl,
        ),
    ]);
    let network = oncl_pki::validation::NetworkPolicy::only_endpoints([
        "http://ocsp.synthetic.test",
        "http://crl.synthetic.test",
    ])
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let source = include_bytes!("fixtures/external-multipage.pdf");
    for ending in [b"\n".as_slice(), b"".as_slice(), b"\r".as_slice()] {
        let mut previous = source.to_vec();
        for name in ["user-rsa-sign", "user-gost2015-sign"] {
            let mut key = issued(name);
            let mut s = scope();
            let mut stage = store.stage(&mut s).unwrap();
            if name == "user-rsa-sign" && ending != b"\n" {
                previous = independent_eof_signature(&previous, ending, &store, &mut key);
                continue;
            }
            let transport = oncl_pki::http::deadline::DeadlineTransport::new(&http, &network, &s);
            let validation = ValidationContext {
                policy: ValidationPolicy::StrictOnline,
                now,
                anchors: &anchors,
                intermediates: &intermediates,
                http: &transport,
            };
            sign_source(
                Source::sequential(&mut Cursor::new(&previous), None),
                &PdfSignProfile::default(),
                &mut key,
                &CmsSignServices::new(Some(&validation), Some(&store)),
                &mut stage,
                &s,
            )
            .unwrap_or_else(|error| panic!("signing {name}: {error:?}"));
            let mut output = Vec::new();
            stage.copy_to(&mut output).unwrap();
            assert!(output.starts_with(&previous));
            previous = output;
        }
        let mut s = scope();
        let mut c = Cursor::new(&previous);
        let doc = PdfDocument::open(
            Source::seekable(&mut c, None),
            &PdfLimits::default(),
            &mut s,
        )
        .unwrap();
        assert_eq!(doc.revision_count(), 3);
        drop(doc);
        assert_eq!(
            lopdf::Document::load_mem(&previous)
                .unwrap()
                .get_pages()
                .len(),
            4
        );
        let mut s = scope();
        let transport = oncl_pki::http::deadline::DeadlineTransport::new(&http, &network, &s);
        let validation = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now,
            anchors: &anchors,
            intermediates: &intermediates,
            http: &transport,
        };
        let report = oncl_pdf::verify_source(
            Source::sequential(&mut Cursor::new(&previous), None),
            &PdfLimits::default(),
            &store,
            &validation,
            &[
                oncl_pki::key::SigAlg::RsaSha256,
                oncl_pki::key::SigAlg::Gost2015_512,
            ],
            &mut s,
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(report.signatures.len(), 2);
        assert!(report.signatures.iter().all(|s| {
            s.validation
                .signers
                .iter()
                .all(|s| s.signature == CheckStatus::Passed)
        }));
        assert!(report.signatures[0].later_changes);
        assert!(!report.signatures[1].later_changes);
        if ending != b"\n" {
            let old = &report.signatures[0];
            assert_eq!(old.parser_revision_end, old.revision_end + 1);
            assert_eq!(
                old.endpoint_scope,
                if ending.is_empty() {
                    oncl_pdf::PdfEndpointScope::HistoricalEof
                } else {
                    oncl_pdf::PdfEndpointScope::HistoricalLineEnding
                }
            );
            let mut broken = previous.clone();
            let offset = broken
                .windows(12)
                .position(|w| w == b"/ByteRange [")
                .unwrap()
                + 12
                + 63;
            let truncated = old.byte_range.values()[3] - ending.len() as u64 - 1;
            broken[offset..offset + 20].copy_from_slice(format!("{truncated:020}").as_bytes());
            assert!(matches!(
                oncl_pdf::verify_source(
                    Source::sequential(&mut Cursor::new(&broken), None),
                    &PdfLimits::default(),
                    &store,
                    &validation,
                    &[
                        oncl_pki::key::SigAlg::RsaSha256,
                        oncl_pki::key::SigAlg::Gost2015_512
                    ],
                    &mut s
                ),
                Err(oncl_pdf::PdfError::Malformed(
                    "signature not reachable in protected revision"
                ))
            ));
            if ending.is_empty() {
                let mut broken = previous.clone();
                broken[old.revision_end as usize] = b'X';
                assert!(matches!(
                    PdfDocument::open(
                        Source::seekable(&mut Cursor::new(&broken), None),
                        &PdfLimits::default(),
                        &mut scope()
                    ),
                    Err(oncl_pdf::PdfError::Malformed("revision EOF token boundary"))
                ));
            }
        }
    }
}
#[test]
fn byte_range_excludes_only_contents() {
    let output = signed(&unsigned(), 16384).unwrap();
    let text = String::from_utf8_lossy(&output);
    let p = text.rfind("/ByteRange [").unwrap() + 12;
    let end = text[p..].find(']').unwrap() + p;
    let r: Vec<usize> = text[p..end]
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(r.len(), 4);
    assert_eq!(r[0], 0);
    assert_eq!(r[2] + r[3], output.len());
    assert_eq!(output[r[1]], b'<');
    assert_eq!(output[r[2] - 1], b'>');
    let hex = &output[r[1] + 1..r[2] - 1];
    let bytes: Vec<u8> = hex
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let cms = oncl_pki::io::padded_der_sequence(&bytes).unwrap();
    let mut data = output[..r[1]].to_vec();
    data.extend_from_slice(&output[r[2]..]);
    assert_eq!(cms::verify(cms, Some(&data)).unwrap().len(), 1);
    data[10] ^= 1;
    assert!(cms::verify(cms, Some(&data)).is_err());
}
#[test]
fn reserved_signature_space_checked() {
    assert!(PdfSignProfile::new(0).is_err());
    assert!(PdfSignProfile::new(usize::MAX).is_err());
    assert!(signed(&unsigned(), 8).is_err());
    assert!(PdfSignProfile::new(16384).is_ok());
}

fn entry(name: &str) -> oncl_pki::pkcs12::KeyEntry {
    let f = oncl_testkit::synthetic(name);
    oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn issued(name: &str) -> oncl_pki::pkcs12::KeyEntry {
    let mut e = entry(name);
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&e.cert);
    let template =
        oncl_pki::testing::TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert);
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions
        .extend(template.extensions.into_iter().filter(|e| {
            matches!(
                e.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        }));
    e.cert = oncl_pki::testing::issue_cert(&entry("inter-gost2015.key"), spec);
    e
}

struct Counted {
    entry: oncl_pki::pkcs12::KeyEntry,
    uses: usize,
}
impl oncl_pki::key::DigestSigner for Counted {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        &self.entry.cert
    }
    fn algorithm(&self) -> oncl_pki::key::SigAlg {
        oncl_pki::key::DigestSigner::algorithm(&self.entry)
    }
    fn sign_digest(
        &mut self,
        digest: &oncl_pki::digest::DigestValue,
    ) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
        self.uses += 1;
        oncl_pki::key::DigestSigner::sign_digest(&mut self.entry, digest)
    }
}
#[test]
fn original_and_output_each_charge_once_and_short_temp_prevents_key_use() {
    let source = include_bytes!("fixtures/external-multipage.pdf");
    let expected = signed(source, 16384).unwrap().len() as u64;
    for short in [0, 1] {
        let limits = ResourceLimits {
            input_bytes: source.len() as u64,
            output_bytes: expected,
            temp_bytes: expected + source.len() as u64 - short,
            ..ResourceLimits::default()
        };
        let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
            .begin(limits, Arc::new(Control))
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        let mut key = Counted {
            entry: entry("user-rsa-sign"),
            uses: 0,
        };
        let result = sign_source(
            Source::seekable(&mut Cursor::new(source), Some(1)),
            &PdfSignProfile::default(),
            &mut key,
            &CmsSignServices::new(None, Some(&store)),
            &mut stage,
            &scope,
        );
        assert_eq!(scope.progress().bytes_in, source.len() as u64);
        if short == 0 {
            let report = result.unwrap();
            assert_eq!(report.bytes_out, expected);
            assert_eq!(scope.progress().bytes_out, expected);
            assert_eq!(key.uses, 1);
            assert!(scope.reserve_temp(source.len() as u64).is_ok());
            let mut bytes = Vec::new();
            stage.copy_to(&mut bytes).unwrap();
            assert!(bytes.starts_with(source));
        } else {
            assert!(matches!(
                result,
                Err(oncl_pdf::PdfError::Processing(ProcessingError::TempLimit))
            ));
            assert_eq!(key.uses, 0);
            assert!(stage.copy_to(&mut Vec::new()).is_err());
        }
    }
}

#[test]
fn catalog_and_form_values_survive_without_version_downgrade() {
    use lopdf::{Object, dictionary};
    let mut doc = lopdf::Document::load_mem(&unsigned()).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let field=doc.add_object(dictionary!{"FT"=>"Tx","T"=>Object::string_literal("Existing"),"V"=>Object::string_literal("Keep original form value")});
    let form=doc.add_object(dictionary!{"Fields"=>vec![Object::Reference(field)],"SigFlags"=>4,"NeedAppearances"=>true});
    let catalog = doc.get_object_mut(root).unwrap().as_dict_mut().unwrap();
    catalog.set("AcroForm", form);
    catalog.set("Version", "2.0");
    catalog.set(
        "ViewerPreferences",
        dictionary! {"HideToolbar"=>true,"CustomReal"=>Object::Real(-1.25)},
    );
    let mut input = Vec::new();
    doc.save_to(&mut input).unwrap();
    let output = signed(&input, 16384).unwrap();
    assert!(output.starts_with(&input));
    let parsed = lopdf::Document::load_mem(&output).unwrap();
    let catalog = parsed.get_object(root).unwrap().as_dict().unwrap();
    assert_eq!(catalog.get(b"Version").unwrap().as_name().unwrap(), b"2.0");
    let preferences = catalog
        .get(b"ViewerPreferences")
        .unwrap()
        .as_dict()
        .unwrap();
    assert!(preferences.get(b"HideToolbar").unwrap().as_bool().unwrap());
    assert_eq!(
        preferences.get(b"CustomReal").unwrap().as_f32().unwrap(),
        -1.25
    );
    let form = parsed
        .get_object(catalog.get(b"AcroForm").unwrap().as_reference().unwrap())
        .unwrap()
        .as_dict()
        .unwrap();
    assert_eq!(form.get(b"SigFlags").unwrap().as_i64().unwrap(), 7);
    assert!(form.get(b"NeedAppearances").unwrap().as_bool().unwrap());
    let fields = form.get(b"Fields").unwrap().as_array().unwrap();
    assert_eq!(fields.len(), 2);
    let existing = parsed
        .get_object(fields[0].as_reference().unwrap())
        .unwrap()
        .as_dict()
        .unwrap();
    assert_eq!(
        existing.get(b"V").unwrap().as_str().unwrap(),
        b"Keep original form value"
    );
}

#[test]
fn reservation_larger_than_reader_object_limit_fails_before_key_use() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope();
    let mut output = store.stage(&mut scope).unwrap();
    let mut key = Counted {
        entry: entry("user-rsa-sign"),
        uses: 0,
    };
    let error = sign_source(
        Source::sequential(&mut Cursor::new(unsigned()), None),
        &PdfSignProfile::new(1_048_576).unwrap(),
        &mut key,
        &CmsSignServices::new(None, Some(&store)),
        &mut output,
        &scope,
    );
    assert!(matches!(error, Err(oncl_pdf::PdfError::Limit(_))));
    assert_eq!(key.uses, 0);
    assert_eq!(scope.progress().bytes_in, 0);
    assert!(output.copy_to(&mut Vec::new()).is_err());
}

// Independent test producer of an actual signed revision with a legal bare
// %%EOF or CR terminator. It does not call the production incremental writer.
fn independent_eof_signature(
    input: &[u8],
    ending: &[u8],
    store: &TemporaryStore,
    key: &mut dyn oncl_pki::key::DigestSigner,
) -> Vec<u8> {
    use oncl_pki::io::PdfSignatureOutput;
    let parsed = lopdf::Document::load_mem(input).unwrap();
    let root = parsed.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let pages = parsed
        .get_object(root)
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"Pages")
        .unwrap()
        .as_reference()
        .unwrap();
    let form = parsed.max_id + 1;
    let field = form + 1;
    let sig = form + 2;
    let marker = input.windows(9).rposition(|w| w == b"startxref").unwrap() + 9;
    let prev: u64 = std::str::from_utf8(&input[marker..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut s = scope();
    let mut stage = store.stage(&mut s).unwrap();
    let mut output = PdfSignatureOutput::new(&mut stage, &s).unwrap();
    output.append(input).unwrap();
    output.append(b"\n").unwrap();
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
        output
            .append(format!("{id} {generation} obj\n{body}\nendobj\n").as_bytes())
            .unwrap();
    }
    offsets.insert((sig, 0), output.len());
    output
        .append(
            format!(
                "{sig} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached"
            )
            .as_bytes(),
        )
        .unwrap();
    output.reserve_contents(16384).unwrap();
    output.append(b" >>\nendobj\n").unwrap();
    let xref = output.len();
    output.append(b"xref\n").unwrap();
    for ((id, generation), offset) in offsets {
        output
            .append(format!("{id} 1\n{offset:010} {generation:05} n \n").as_bytes())
            .unwrap();
    }
    output
        .append(
            format!(
                "trailer\n<< /Size {} /Root {} {} R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF",
                sig + 1,
                root.0,
                root.1
            )
            .as_bytes(),
        )
        .unwrap();
    output.append(ending).unwrap();
    output
        .finish(key, &CmsSignServices::new(None, Some(store)), &s)
        .unwrap();
    let mut bytes = Vec::new();
    stage.copy_to(&mut bytes).unwrap();
    bytes
}
