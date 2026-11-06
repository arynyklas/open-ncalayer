//! P03: real PDF evidence, immutable extension and protected revision controls.
#![cfg(feature = "testing")]
use oncl_pdf::{PdfLimits, PdfSignProfile, ades};
use oncl_pki::{
    cms::ades::{AdesServices, ValidationMaterial},
    crl::MockCrl,
    evidence::{AdesLevel, EvidenceLimits},
    io::{Source, TemporaryStore},
    key::{PrivateKey, SigAlg},
    pkcs12::{KeyEntry, load},
    pkix::CaSet,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
    testing::{TestCertSpec, issue_cert},
    tsp::{MockTsa, TsaMethod, TsaProfile, TsaSpec},
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use std::{io::Cursor, sync::Arc};
use time::{OffsetDateTime, macros::datetime};
const NOW: OffsetDateTime = datetime!(2026-11-03 12:00 UTC);
const URL: &str = "http://127.0.0.1:47819/tsa";
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope() -> ResourceScope {
    let limits = ResourceLimits {
        memory_bytes: 1 << 30,
        metadata_bytes: 64 << 20,
        temp_bytes: 256 << 20,
        ..ResourceLimits::default()
    };
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
fn entry(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}
struct Fixture {
    doc: KeyEntry,
    tsa: KeyEntry,
    root: KeyEntry,
    anchors: CaSet,
    crl: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let mut root = entry("user-rsa-sign");
        root.key = PrivateKey::from_pkcs8_der(
            include_bytes!("../../../fixtures/openssl/rsa.pk8.der"),
            None,
        )
        .unwrap();
        let mut spec = TestCertSpec::from_cert(&entry("root-gost2015.key").cert);
        spec.subject = root.cert.tbs_certificate().subject().clone();
        spec.public_key = root.key.public_key().to_spki();
        spec.serial = vec![0x63, 0x17, 1];
        strip(&mut spec);
        root.cert = issue_cert(&root, spec);
        let mut doc = entry("user-rsa-sign");
        let mut spec = TestCertSpec::from_cert(&doc.cert);
        spec.serial = vec![0x63, 0x17, 2];
        strip(&mut spec);
        doc.cert = issue_cert(&root, spec);
        let mut tsa = doc.clone();
        let mut spec = TestCertSpec::from_cert(&entry("tsa-gost2015").cert);
        spec.public_key = tsa.key.public_key().to_spki();
        spec.serial = vec![0x63, 0x17, 3];
        strip(&mut spec);
        tsa.cert = issue_cert(&root, spec);
        let crl = MockCrl::new(root.clone())
            .with_this_update(NOW - time::Duration::MINUTE)
            .next_update(Some(NOW + time::Duration::HOUR))
            .der();
        Self {
            anchors: CaSet::new(vec![root.cert.clone()]),
            root,
            doc,
            tsa,
            crl,
        }
    }
    fn run(&self, old: Option<&[u8]>, level: AdesLevel) -> (Vec<u8>, ades::PadesReport) {
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let http = MockTsa::new(self.tsa.clone()).with_gen_time(NOW);
        let validation = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &self.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let mut profile = TsaProfile::kalkan_default();
        profile.url = URL.into();
        profile.method = TsaMethod::Post;
        let tsa = TsaSpec::from(profile);
        let certs = [self.doc.cert.clone(), self.tsa.cert.clone()];
        let crls = [self.crl.as_slice()];
        let services = AdesServices {
            validation: &validation,
            host_clock: None,
            network: &network,
            temporary: &store,
            limits: EvidenceLimits {
                max_items: 64,
                max_bytes: 8 << 20,
                max_item_bytes: 1 << 20,
                max_chain_len: 8,
                max_proofs: 16,
                max_coverage_parts: 1024,
                max_coverage_bytes: 10_737_418_240,
            },
            tsa: Some(&tsa),
            material: ValidationMaterial {
                certificates: &certs,
                ocsp: &[],
                crls: &crls,
            },
        };
        let mut s = scope();
        let mut output = store.stage(&mut s).unwrap();
        if let Some(old) = old {
            ades::extend(
                level,
                Source::sequential(&mut Cursor::new(old), None),
                &PdfLimits::default(),
                &services,
                &[SigAlg::RsaSha256],
                &mut output,
                &s,
            )
            .unwrap();
        } else {
            ades::sign(
                level,
                Source::sequential(
                    &mut Cursor::new(include_bytes!("fixtures/external-multipage.pdf")),
                    None,
                ),
                &PdfSignProfile::default(),
                &mut self.doc.clone(),
                &services,
                &mut output,
                &s,
            )
            .unwrap();
        }
        let mut bytes = Vec::new();
        output.copy_to(&mut bytes).unwrap();
        let checked = ades::verify(
            level,
            Source::sequential(&mut Cursor::new(&bytes), None),
            &PdfLimits::default(),
            &services,
            &[SigAlg::RsaSha256],
            &mut s,
        )
        .unwrap();
        assert_eq!(checked.verdict, Verdict::Valid);
        assert_eq!(checked.level(), Some(level));
        assert_eq!(
            lopdf::Document::load_mem(&bytes).unwrap().get_pages().len(),
            4
        );
        (bytes, checked)
    }
    fn inspect(
        &self,
        bytes: &[u8],
        required: AdesLevel,
        now: OffsetDateTime,
        crl: &[u8],
    ) -> Result<ades::PadesReport, oncl_pdf::PdfError> {
        self.context(now, crl, |services| {
            ades::verify(
                required,
                Source::sequential(&mut Cursor::new(bytes), None),
                &PdfLimits::default(),
                services,
                &[SigAlg::RsaSha256],
                &mut scope(),
            )
        })
    }
    fn context<T>(
        &self,
        now: OffsetDateTime,
        crl: &[u8],
        action: impl FnOnce(&AdesServices<'_>) -> T,
    ) -> T {
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let http = MockTsa::new(self.tsa.clone()).with_gen_time(now);
        let validation = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now,
            anchors: &self.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let certs = [
            self.doc.cert.clone(),
            self.tsa.cert.clone(),
            self.root.cert.clone(),
        ];
        let crls = if crl.is_empty() {
            Vec::new()
        } else {
            vec![crl]
        };
        let services = AdesServices {
            validation: &validation,
            host_clock: None,
            network: &network,
            temporary: &store,
            limits: EvidenceLimits {
                max_items: 64,
                max_bytes: 8 << 20,
                max_item_bytes: 1 << 20,
                max_chain_len: 8,
                max_proofs: 16,
                max_coverage_parts: 1024,
                max_coverage_bytes: 10_737_418_240,
            },
            tsa: None,
            material: ValidationMaterial {
                certificates: &certs,
                ocsp: &[],
                crls: &crls,
            },
        };
        action(&services)
    }
    fn rejected(&self, bytes: &[u8]) {
        assert!(
            !self
                .inspect(bytes, AdesLevel::B, NOW, &self.crl)
                .is_ok_and(|r| r.verdict == Verdict::Valid)
        );
        self.context(NOW, &self.crl, |services| {
            let mut s = scope();
            let mut output = services.temporary.stage(&mut s).unwrap();
            assert!(
                ades::extend(
                    AdesLevel::Lta,
                    Source::sequential(&mut Cursor::new(bytes), None),
                    &PdfLimits::default(),
                    services,
                    &[SigAlg::RsaSha256],
                    &mut output,
                    &s
                )
                .is_err()
            );
            assert!(output.copy_to(&mut Vec::new()).is_err());
        });
    }
}
#[test]
fn lt_lta_extend_without_content_resign() {
    let f = Fixture::new();
    let (b, _) = f.run(None, AdesLevel::B);
    let (t, _) = f.run(None, AdesLevel::T);
    assert_ne!(b, t);
    let (lt, _) = f.run(Some(&t), AdesLevel::Lt);
    assert!(lt.starts_with(&t));
    let (lta, _) = f.run(Some(&lt), AdesLevel::Lta);
    assert!(lta.starts_with(&lt));
    let (renewed, _) = f.run(Some(&lta), AdesLevel::Lta);
    assert!(renewed.starts_with(&lta));
}
#[test]
fn document_timestamp_and_dss_tamper() {
    let f = Fixture::new();
    let (lta, _) = f.run(None, AdesLevel::Lta);
    let doc = lopdf::Document::load_mem(&lta).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    assert!(doc.get_object(root).unwrap().as_dict().unwrap().has(b"DSS"));
    assert!(doc.objects.values().any(|v| v.as_dict().is_ok_and(|d| {
        d.get(b"Type")
            .is_ok_and(|v| v.as_name().is_ok_and(|n| n == b"DocTimeStamp"))
    })));
    let mut dss = lta.clone();
    let offset = dss
        .windows(f.crl.len())
        .position(|part| part == f.crl)
        .unwrap();
    dss[offset + f.crl.len() - 1] ^= 1;
    f.rejected(&dss);
    let mut timestamp = lta.clone();
    let start = timestamp
        .windows(b"/ETSI.RFC3161".len())
        .position(|part| part == b"/ETSI.RFC3161")
        .unwrap();
    let gap = start
        + timestamp[start..]
            .windows(11)
            .position(|part| part == b"/Contents <")
            .unwrap()
        + 11;
    timestamp[gap + 100] ^= 1;
    f.rejected(&timestamp);
}
#[test]
fn revocation_after_proven_time() {
    let f = Fixture::new();
    let (t, _) = f.run(None, AdesLevel::T);
    let now = NOW + time::Duration::MINUTE;
    let revoked = MockCrl::new(f.root.clone())
        .with_this_update(now - time::Duration::SECOND)
        .next_update(Some(now + time::Duration::HOUR))
        .revoke(
            f.doc.cert.tbs_certificate().serial_number().as_bytes(),
            NOW + time::Duration::SECOND,
        )
        .der();
    let report = f.inspect(&t, AdesLevel::T, now, &revoked).unwrap();
    assert_eq!(report.verdict, Verdict::Valid);
    let signer = &report.signatures()[0].validation.signers[0];
    assert_eq!(signer.proof_time.as_ref().unwrap().at(), NOW);
    assert!(signer.reasons.iter().any(|r| matches!(
        r,
        oncl_pki::validation::ValidationReason::RevokedAfterProvenTime { .. }
    )));
    let before = MockCrl::new(f.root.clone())
        .with_this_update(now - time::Duration::SECOND)
        .next_update(Some(now + time::Duration::HOUR))
        .revoke(
            f.doc.cert.tbs_certificate().serial_number().as_bytes(),
            NOW - time::Duration::SECOND,
        )
        .der();
    assert_ne!(
        f.inspect(&t, AdesLevel::T, now, &before).unwrap().verdict,
        Verdict::Valid
    );
}

fn encode_object(value: &lopdf::Object, out: &mut Vec<u8>) {
    use lopdf::Object;
    match value {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Object::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Object::Real(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Object::Name(name) => {
            out.push(b'/');
            for b in name {
                out.extend_from_slice(format!("#{b:02X}").as_bytes());
            }
        }
        Object::String(bytes, _) => {
            out.push(b'<');
            for b in bytes {
                out.extend_from_slice(format!("{b:02X}").as_bytes());
            }
            out.push(b'>');
        }
        Object::Reference((id, generation)) => {
            out.extend_from_slice(format!("{id} {generation} R").as_bytes())
        }
        Object::Array(values) => {
            out.push(b'[');
            for value in values {
                encode_object(value, out);
                out.push(b' ');
            }
            out.push(b']');
        }
        Object::Dictionary(values) => {
            out.extend_from_slice(b"<<");
            for (key, value) in values {
                encode_object(&Object::Name(key.clone()), out);
                out.push(b' ');
                encode_object(value, out);
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
        }
        Object::Stream(_) => panic!("attack helper only serializes dictionary metadata"),
    }
}
fn append_objects(bytes: &[u8], objects: Vec<(lopdf::ObjectId, lopdf::Object)>) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    let marker = bytes.windows(9).rposition(|b| b == b"startxref").unwrap() + 9;
    let previous = std::str::from_utf8(&bytes[marker..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let mut result = bytes.to_vec();
    result.push(b'\n');
    let mut offsets = Vec::new();
    for ((id, generation), value) in objects {
        offsets.push((id, generation, result.len()));
        result.extend_from_slice(format!("{id} {generation} obj\n").as_bytes());
        encode_object(&value, &mut result);
        result.extend_from_slice(b"\nendobj\n");
    }
    offsets.sort_unstable();
    let xref = result.len();
    result.extend_from_slice(b"xref\n");
    for (id, generation, offset) in offsets {
        result.extend_from_slice(format!("{id} 1\n{offset:010} {generation:05} n \n").as_bytes());
    }
    result.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Prev {previous} /Root ",
            doc.max_id + 1
        )
        .as_bytes(),
    );
    encode_object(doc.trailer.get(b"Root").unwrap(), &mut result);
    for key in [b"Info".as_slice(), b"ID"] {
        if let Ok(value) = doc.trailer.get(key) {
            result.push(b' ');
            encode_object(&lopdf::Object::Name(key.to_vec()), &mut result);
            result.push(b' ');
            encode_object(value, &mut result);
        }
    }
    result.extend_from_slice(format!(" >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    result
}
/// Appends an object-less increment with a hand-written xref section and trailer ID.
fn append_trailer_only(
    bytes: &[u8],
    free_entries: &[u32],
    id: Option<(Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    let marker = bytes.windows(9).rposition(|b| b == b"startxref").unwrap() + 9;
    let previous = std::str::from_utf8(&bytes[marker..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let mut result = bytes.to_vec();
    result.push(b'\n');
    let xref = result.len();
    result.extend_from_slice(b"xref\n");
    for id in free_entries {
        let line = if *id == 0 {
            "0 1\n0000000000 65535 f \n".to_string()
        } else {
            format!("{id} 1\n0000000000 00001 f \n")
        };
        result.extend_from_slice(line.as_bytes());
    }
    result.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Prev {previous} /Root ",
            doc.max_id + 1
        )
        .as_bytes(),
    );
    encode_object(doc.trailer.get(b"Root").unwrap(), &mut result);
    if let Ok(value) = doc.trailer.get(b"Info") {
        result.extend_from_slice(b" /Info ");
        encode_object(value, &mut result);
    }
    if let Some((a, b)) = id {
        let hex = |v: Vec<u8>| v.iter().map(|b| format!("{b:02X}")).collect::<String>();
        result.extend_from_slice(format!(" /ID [<{}> <{}>]", hex(a), hex(b)).as_bytes());
    }
    result.extend_from_slice(format!(" >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    result
}
fn trailer_id(bytes: &[u8]) -> Vec<Vec<u8>> {
    let doc = lopdf::Document::load_mem(bytes).unwrap();
    doc.trailer
        .get(b"ID")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_vec())
        .collect()
}
fn permitted_or(f: &Fixture, bytes: &[u8]) -> Result<(), String> {
    match f.inspect(bytes, AdesLevel::B, NOW, &f.crl) {
        Err(oncl_pdf::PdfError::Unsupported(m)) => Err(m.to_string()),
        _ => Ok(()),
    }
}
#[test]
fn update_may_change_trailer_id_instance_and_relist_free_head_only() {
    let f = Fixture::new();
    let (lt, _) = f.run(None, AdesLevel::Lt);
    let ids = trailer_id(&lt);
    let original = ids[0].clone();
    // ID[1] changes, ID[0] preserved, object 0 free head re-listed: valid update.
    let valid = append_trailer_only(&lt, &[0], Some((original.clone(), vec![9, 8, 7, 6])));
    assert_eq!(permitted_or(&f, &valid), Ok(()));
    // ID[0] substitution is refused.
    let swapped = append_trailer_only(&lt, &[0], Some((vec![1; ids[0].len()], vec![9, 8, 7, 6])));
    assert_eq!(
        permitted_or(&f, &swapped),
        Err("incremental trailer metadata change".into())
    );
    // Deleting (freeing) a real object is refused; only the object 0 head is exempt.
    let doc = lopdf::Document::load_mem(&lt).unwrap();
    let page = doc.get_pages().values().next().unwrap().0;
    let deleted = append_trailer_only(&lt, &[0, page], Some((original.clone(), vec![9, 8, 7, 6])));
    assert_eq!(
        permitted_or(&f, &deleted),
        Err("free or compressed augmentation entry".into())
    );
}
#[test]
fn validation_update_cannot_alias_existing_page_as_acroform() {
    let f = Fixture::new();
    let (lta, _) = f.run(None, AdesLevel::Lta);
    let doc = lopdf::Document::load_mem(&lta).unwrap();
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let mut catalog = doc.get_object(root).unwrap().as_dict().unwrap().clone();
    let form = catalog.get(b"AcroForm").unwrap().as_reference().unwrap();
    let page = *doc.get_pages().values().next().unwrap();
    catalog.set("AcroForm", lopdf::Object::Reference(page));
    let forged = append_objects(
        &lta,
        vec![
            (page, doc.get_object(form).unwrap().clone()),
            (root, lopdf::Object::Dictionary(catalog)),
        ],
    );
    f.rejected(&forged);
}
#[test]
fn unsigned_page_catalog_permission_and_field_changes_are_not_validation() {
    let f = Fixture::new();
    let (lta, _) = f.run(None, AdesLevel::Lta);
    let doc = lopdf::Document::load_mem(&lta).unwrap();
    let page = *doc.get_pages().values().next().unwrap();
    let mut page_value = doc.get_object(page).unwrap().as_dict().unwrap().clone();
    page_value.set("MediaBox", vec![0.into(), 0.into(), 1.into(), 1.into()]);
    f.rejected(&append_objects(
        &lta,
        vec![(page, lopdf::Object::Dictionary(page_value))],
    ));
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    for key in ["PageMode", "Perms"] {
        let mut catalog = doc.get_object(root).unwrap().as_dict().unwrap().clone();
        catalog.set(key, lopdf::Object::Name(b"Forged".to_vec()));
        f.rejected(&append_objects(
            &lta,
            vec![(root, lopdf::Object::Dictionary(catalog))],
        ));
    }
}
#[test]
fn b_to_t_uses_raw_document_imprint_and_retains_every_old_signature() {
    let f = Fixture::new();
    let (b, _) = f.run(None, AdesLevel::B);
    let (t, report) = f.run(Some(&b), AdesLevel::T);
    assert!(t.starts_with(&b));
    assert!(
        report.signatures()[0].validation.signers[0]
            .proof_time
            .is_some()
    );
    let doc = lopdf::Document::load_mem(&t).unwrap();
    for value in doc.objects.values() {
        let Ok(dict) = value.as_dict() else {
            continue;
        };
        if !dict
            .get(b"Type")
            .is_ok_and(|v| v.as_name().is_ok_and(|n| n == b"DocTimeStamp"))
        {
            continue;
        }
        let ranges: Vec<_> = dict
            .get(b"ByteRange")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap() as usize)
            .collect();
        let mut hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Sha256);
        hash.update(&t[ranges[0]..ranges[0] + ranges[1]]);
        hash.update(&t[ranges[2]..ranges[2] + ranges[3]]);
        let token =
            oncl_pki::io::padded_der_sequence(dict.get(b"Contents").unwrap().as_str().unwrap())
                .unwrap();
        oncl_pki::tsp::verify_token_imprint(token, &hash.finish()).unwrap();
        let mut changed = t.clone();
        changed[ranges[1] - 1] ^= 1;
        f.rejected(&changed);
    }
}

#[test]
fn multisigner_augmentation_preserves_existing_vri_entries() {
    fn vri(bytes: &[u8]) -> lopdf::Dictionary {
        let doc = lopdf::Document::load_mem(bytes).unwrap();
        let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
        let catalog = doc.get_object(root).unwrap().as_dict().unwrap();
        let dss = doc
            .get_object(catalog.get(b"DSS").unwrap().as_reference().unwrap())
            .unwrap()
            .as_dict()
            .unwrap();
        doc.get_object(dss.get(b"VRI").unwrap().as_reference().unwrap())
            .unwrap()
            .as_dict()
            .unwrap()
            .clone()
    }
    let mut f = Fixture::new();
    let (first, _) = f.run(None, AdesLevel::Lta);
    let before = vri(&first);
    let mut spec = TestCertSpec::from_cert(&f.doc.cert);
    spec.serial = vec![0x63, 0x17, 8];
    f.doc.cert = issue_cert(&f.root, spec);
    let second = f.context(NOW, &f.crl, |services| {
        let mut profile = TsaProfile::kalkan_default();
        profile.url = URL.into();
        profile.method = TsaMethod::Post;
        let tsa = TsaSpec::from(profile);
        let configured = AdesServices {
            validation: services.validation,
            host_clock: services.host_clock,
            network: services.network,
            temporary: services.temporary,
            limits: services.limits,
            tsa: Some(&tsa),
            material: ValidationMaterial {
                certificates: services.material.certificates,
                ocsp: services.material.ocsp,
                crls: services.material.crls,
            },
        };
        let mut s = scope();
        let mut output = services.temporary.stage(&mut s).unwrap();
        ades::sign(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&first), None),
            &PdfSignProfile::default(),
            &mut f.doc.clone(),
            &configured,
            &mut output,
            &s,
        )
        .unwrap();
        let mut bytes = Vec::new();
        output.copy_to(&mut bytes).unwrap();
        bytes
    });
    assert!(second.starts_with(&first));
    let after = vri(&second);
    for (key, value) in &before {
        let mut expected = Vec::new();
        encode_object(value, &mut expected);
        let mut actual = Vec::new();
        encode_object(after.get(key).unwrap(), &mut actual);
        assert_eq!(
            actual, expected,
            "an existing signature VRI must remain unchanged"
        );
    }
    assert!(after.len() > before.len());
    assert_eq!(
        f.inspect(&second, AdesLevel::Lta, NOW, &f.crl)
            .unwrap()
            .signatures()
            .len(),
        2
    );
}

fn with_tsa<T>(
    f: &Fixture,
    now: OffsetDateTime,
    gen_time: OffsetDateTime,
    action: impl FnOnce(&AdesServices<'_>) -> T,
) -> T {
    with_tsa_counted(f, now, gen_time, |services, _| action(services))
}
fn with_tsa_counted<T>(
    f: &Fixture,
    now: OffsetDateTime,
    gen_time: OffsetDateTime,
    action: impl FnOnce(&AdesServices<'_>, &MockTsa) -> T,
) -> T {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let http = MockTsa::new(f.tsa.clone()).with_gen_time(gen_time);
    let validation = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &f.anchors,
        intermediates: &[],
        http: &http,
    };
    let network = NetworkPolicy::only_endpoints([URL]).unwrap();
    let certs = [f.doc.cert.clone(), f.tsa.cert.clone(), f.root.cert.clone()];
    let crls = [f.crl.as_slice()];
    let mut profile = TsaProfile::kalkan_default();
    profile.url = URL.into();
    profile.method = TsaMethod::Post;
    let mut tsa = TsaSpec::from(profile);
    tsa.check_skew = None;
    let services = AdesServices {
        validation: &validation,
        host_clock: None,
        network: &network,
        temporary: &store,
        limits: EvidenceLimits {
            max_items: 64,
            max_bytes: 8 << 20,
            max_item_bytes: 1 << 20,
            max_chain_len: 8,
            max_proofs: 16,
            max_coverage_parts: 1024,
            max_coverage_bytes: 10_737_418_240,
        },
        tsa: Some(&tsa),
        material: ValidationMaterial {
            certificates: &certs,
            ocsp: &[],
            crls: &crls,
        },
    };
    action(&services, &http)
}
struct CountSigner {
    key: KeyEntry,
    calls: usize,
}
impl oncl_pki::key::DigestSigner for CountSigner {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        &self.key.cert
    }
    fn algorithm(&self) -> SigAlg {
        oncl_pki::key::DigestSigner::algorithm(&self.key)
    }
    fn sign_digest(
        &mut self,
        digest: &oncl_pki::digest::DigestValue,
    ) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
        self.calls += 1;
        oncl_pki::key::DigestSigner::sign_digest(&mut self.key, digest)
    }
}
#[test]
fn missing_acquisition_is_not_applied_but_future_and_untrusted_tsa_fail_after_one_use() {
    let mut f = Fixture::new();
    f.context(NOW, &f.crl, |services| {
        let mut s = scope();
        let mut output = services.temporary.stage(&mut s).unwrap();
        let mut signer = CountSigner {
            key: f.doc.clone(),
            calls: 0,
        };
        assert!(
            ades::sign(
                AdesLevel::T,
                Source::sequential(
                    &mut Cursor::new(include_bytes!("fixtures/external-multipage.pdf")),
                    None
                ),
                &PdfSignProfile::default(),
                &mut signer,
                services,
                &mut output,
                &s
            )
            .is_err()
        );
        assert_eq!(signer.calls, 0);
        assert!(output.copy_to(&mut Vec::new()).is_err());
    });
    for untrusted in [false, true] {
        if untrusted {
            let issuer = f.tsa.clone();
            f.tsa.cert = issue_cert(&issuer, TestCertSpec::from_cert(&issuer.cert));
        }
        with_tsa(
            &f,
            NOW,
            if untrusted {
                NOW
            } else {
                NOW + time::Duration::SECOND
            },
            |services| {
                let mut s = scope();
                let mut output = services.temporary.stage(&mut s).unwrap();
                let mut signer = CountSigner {
                    key: f.doc.clone(),
                    calls: 0,
                };
                let error = ades::sign(
                    AdesLevel::T,
                    Source::sequential(
                        &mut Cursor::new(include_bytes!("fixtures/external-multipage.pdf")),
                        None,
                    ),
                    &PdfSignProfile::default(),
                    &mut signer,
                    services,
                    &mut output,
                    &s,
                )
                .unwrap_err();
                assert!(matches!(
                    error,
                    oncl_pdf::PdfError::Ades(oncl_pki::cms::ades::AdesError::AfterKeyUse {
                        applied: oncl_pki::key::AppliedState::Applied,
                        ..
                    })
                ));
                assert_eq!(signer.calls, 1);
                assert!(output.copy_to(&mut Vec::new()).is_err());
            },
        );
    }
}
#[test]
fn required_level_is_not_achieved_and_tsa_status_is_current_not_token_presence() {
    let f = Fixture::new();
    let (t, _) = f.run(None, AdesLevel::T);
    assert_eq!(
        f.inspect(&t, AdesLevel::B, NOW, &f.crl).unwrap().level(),
        Some(AdesLevel::T)
    );
    let missing_dss = f.inspect(&t, AdesLevel::Lt, NOW, &f.crl).unwrap();
    assert_ne!(missing_dss.verdict, Verdict::Valid);
    assert_eq!(missing_dss.level(), None);
    assert_ne!(
        f.inspect(&t, AdesLevel::T, NOW, &[]).unwrap().verdict,
        Verdict::Valid
    );
    let (lta, _) = f.run(None, AdesLevel::Lta);
    assert_eq!(
        f.inspect(&lta, AdesLevel::B, NOW, &[]).unwrap().level(),
        Some(AdesLevel::Lta)
    );
    assert_ne!(
        f.inspect(&lta, AdesLevel::B, NOW + time::Duration::hours(2), &[])
            .unwrap()
            .verdict,
        Verdict::Valid
    );
}
#[test]
fn expired_now_requires_real_proven_time_not_pdf_claimed_date() {
    use der::asn1::UtcTime;
    let mut f = Fixture::new();
    let mut spec = TestCertSpec::from_cert(&f.doc.cert);
    spec.validity.not_after = x509_cert::time::Time::UtcTime(
        UtcTime::from_unix_duration(std::time::Duration::from_secs(
            (NOW + time::Duration::SECOND).unix_timestamp() as u64,
        ))
        .unwrap(),
    );
    f.doc.cert = issue_cert(&f.root, spec);
    let (b, _) = f.run(None, AdesLevel::B);
    let (t, _) = f.run(None, AdesLevel::T);
    let later = NOW + time::Duration::seconds(10);
    assert_ne!(
        f.inspect(&b, AdesLevel::B, later, &f.crl).unwrap().verdict,
        Verdict::Valid
    );
    let proven = f.inspect(&t, AdesLevel::T, later, &f.crl).unwrap();
    assert_eq!(proven.verdict, Verdict::Valid);
    assert_eq!(
        proven.signatures()[0].validation.signers[0]
            .proof_time
            .as_ref()
            .unwrap()
            .at(),
        NOW
    );
}
#[test]
fn backdated_renewal_cannot_launder_old_archive_and_never_publishes() {
    let f = Fixture::new();
    let (lta, _) = f.run(None, AdesLevel::Lta);
    with_tsa(
        &f,
        NOW + time::Duration::MINUTE,
        NOW - time::Duration::SECOND,
        |services| {
            let mut s = scope();
            let mut output = services.temporary.stage(&mut s).unwrap();
            assert!(
                ades::extend(
                    AdesLevel::Lta,
                    Source::sequential(&mut Cursor::new(&lta), None),
                    &PdfLimits::default(),
                    services,
                    &[SigAlg::RsaSha256],
                    &mut output,
                    &s
                )
                .is_err()
            );
            assert!(output.copy_to(&mut Vec::new()).is_err());
        },
    );
}
#[test]
fn pades_original_intake_and_final_output_are_counted_once_with_exact_quotas() {
    let f = Fixture::new();
    let (reference, _) = f.run(None, AdesLevel::Lta);
    let source = include_bytes!("fixtures/external-multipage.pdf");
    for short in [false, true] {
        with_tsa(&f, NOW, NOW, |services| {
            let limits = ResourceLimits {
                input_bytes: source.len() as u64,
                output_bytes: reference.len() as u64 - u64::from(short),
                ..ResourceLimits::default()
            };
            let mut s = Arc::new(SharedBudget::new(limits.clone()).unwrap())
                .begin(limits, Arc::new(Control))
                .unwrap();
            let mut output = services.temporary.stage(&mut s).unwrap();
            let mut signer = CountSigner {
                key: f.doc.clone(),
                calls: 0,
            };
            let result = ades::sign(
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(source), Some(1)),
                &PdfSignProfile::default(),
                &mut signer,
                services,
                &mut output,
                &s,
            );
            assert_eq!(signer.calls, 1);
            assert_eq!(s.progress().bytes_in, source.len() as u64);
            if short {
                assert!(matches!(
                    result,
                    Err(oncl_pdf::PdfError::Ades(
                        oncl_pki::cms::ades::AdesError::AfterKeyUse {
                            applied: oncl_pki::key::AppliedState::Applied,
                            ..
                        }
                    ))
                ));
                assert!(output.copy_to(&mut Vec::new()).is_err());
            } else {
                result.unwrap();
                assert_eq!(s.progress().bytes_out, reference.len() as u64);
                let mut bytes = Vec::new();
                output.copy_to(&mut bytes).unwrap();
                assert_eq!(bytes.len(), reference.len());
                assert_eq!(s.progress().bytes_out, reference.len() as u64);
            }
        });
    }
}
#[test]
fn incremental_revision_limit_is_enforced_on_verify_and_extension() {
    let f = Fixture::new();
    let (lta, _) = f.run(None, AdesLevel::Lta);
    f.context(NOW, &f.crl, |services| {
        let limits = PdfLimits {
            max_revisions: 3,
            ..PdfLimits::default()
        };
        assert!(matches!(
            ades::verify(
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(&lta), None),
                &limits,
                services,
                &[SigAlg::RsaSha256],
                &mut scope()
            ),
            Err(oncl_pdf::PdfError::Limit(_))
        ));
        let mut s = scope();
        let mut output = services.temporary.stage(&mut s).unwrap();
        assert!(
            ades::extend(
                AdesLevel::B,
                Source::sequential(&mut Cursor::new(&lta), None),
                &limits,
                services,
                &[SigAlg::RsaSha256],
                &mut output,
                &s
            )
            .is_err()
        );
        assert!(output.copy_to(&mut Vec::new()).is_err());
    });
}

#[test]
fn closed_document_proof_rejects_foreign_snapshot_wrong_imprint_and_own_gap() {
    use oncl_pki::{
        cms::ades::{SnapshotDocumentTimestamp, SnapshotSignature, verify_snapshot_pades},
        io::{FrozenInput, PdfSnapshot, Region, SnapshotEncoding},
    };
    use std::sync::Mutex;
    let f = Fixture::new();
    let (b, _) = f.run(None, AdesLevel::B);
    let (t, _) = f.run(Some(&b), AdesLevel::T);
    let doc = lopdf::Document::load_mem(&t).unwrap();
    let range = |dict: &lopdf::Dictionary| -> ([Region; 2], Region) {
        let r: Vec<_> = dict
            .get(b"ByteRange")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap() as u64)
            .collect();
        (
            [
                Region {
                    offset: r[0],
                    len: r[1],
                },
                Region {
                    offset: r[2],
                    len: r[3],
                },
            ],
            Region {
                offset: r[1],
                len: r[2] - r[1],
            },
        )
    };
    let mut regular = None;
    let mut timestamp = None;
    for object in doc.objects.values() {
        let Ok(dict) = object.as_dict() else {
            continue;
        };
        if dict
            .get(b"Type")
            .is_ok_and(|v| v.as_name().is_ok_and(|n| n == b"Sig"))
        {
            regular = Some(range(dict));
        }
        if dict
            .get(b"Type")
            .is_ok_and(|v| v.as_name().is_ok_and(|n| n == b"DocTimeStamp"))
        {
            timestamp = Some(range(dict));
        }
    }
    let (signed_ranges, cms_gap) = regular.unwrap();
    let (document_ranges, token_gap) = timestamp.unwrap();
    f.context(NOW, &f.crl, |services| {
        let mut s = scope();
        let mut frozen = FrozenInput::capture(
            Source::sequential(&mut Cursor::new(&t), None),
            services.temporary,
            &mut s,
        )
        .unwrap();
        let mut snapshot = PdfSnapshot::input(&mut frozen, &s).unwrap();
        let cms = snapshot
            .derive_region(cms_gap, &s, SnapshotEncoding::PdfByteString)
            .unwrap();
        let token = snapshot
            .derive_region(token_gap, &s, SnapshotEncoding::PdfByteString)
            .unwrap();
        let snapshot = Mutex::new(snapshot);
        let documents = [SnapshotDocumentTimestamp {
            token: &token,
            regions: document_ranges,
        }];
        assert_eq!(
            verify_snapshot_pades(
                AdesLevel::T,
                &[SnapshotSignature {
                    metadata: &cms,
                    regions: signed_ranges
                }],
                &snapshot,
                &[],
                &documents,
                services,
                &[SigAlg::RsaSha256],
                &s
            )
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .verdict,
            Verdict::Valid
        );
        for own_gap in [false, true] {
            let mut forged = document_ranges;
            if own_gap {
                forged[0].len += 1;
            } else {
                forged[1].len -= 1;
            }
            let documents = [SnapshotDocumentTimestamp {
                token: &token,
                regions: forged,
            }];
            assert!(
                !verify_snapshot_pades(
                    AdesLevel::T,
                    &[SnapshotSignature {
                        metadata: &cms,
                        regions: signed_ranges
                    }],
                    &snapshot,
                    &[],
                    &documents,
                    services,
                    &[SigAlg::RsaSha256],
                    &s
                )
                .is_ok_and(|reports| reports.into_iter().next().unwrap().verdict == Verdict::Valid)
            );
        }
        let mut other = FrozenInput::capture(
            Source::sequential(&mut Cursor::new(&t), None),
            services.temporary,
            &mut s,
        )
        .unwrap();
        let mut other_view = PdfSnapshot::input(&mut other, &s).unwrap();
        let foreign = other_view
            .derive_region(cms_gap, &s, SnapshotEncoding::PdfByteString)
            .unwrap();
        assert!(
            verify_snapshot_pades(
                AdesLevel::T,
                &[SnapshotSignature {
                    metadata: &foreign,
                    regions: signed_ranges
                }],
                &snapshot,
                &[],
                &documents,
                services,
                &[SigAlg::RsaSha256],
                &s
            )
            .is_err()
        );
    });
}

#[test]
fn initial_signed_catalog_permissions_are_not_silently_accepted() {
    use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
    let f = Fixture::new();
    let (mut bytes, _) = f.run(None, AdesLevel::B);
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let (id, signature) = doc
        .objects
        .iter()
        .find_map(|(id, value)| {
            value
                .as_dict()
                .ok()
                .filter(|d| {
                    d.get(b"Type")
                        .is_ok_and(|v| v.as_name().is_ok_and(|n| n == b"Sig"))
                })
                .map(|dict| (*id, dict))
        })
        .unwrap();
    let range: Vec<_> = signature
        .get(b"ByteRange")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap() as usize)
        .collect();
    let version = b"/#56#65#72#73#69#6F#6E /#31#2E#37";
    let at = bytes
        .windows(version.len())
        .position(|part| part == version)
        .unwrap();
    let permission = format!("/Perms << /DocMDP {} {} R >>", id.0, id.1);
    assert!(permission.len() <= version.len());
    bytes[at..at + version.len()].fill(b' ');
    bytes[at..at + permission.len()].copy_from_slice(permission.as_bytes());
    let mut protected = bytes[..range[1]].to_vec();
    protected.extend_from_slice(&bytes[range[2]..range[2] + range[3]]);
    let mut attrs = AttrSpec::cades(NOW);
    attrs.signing_time = None;
    let cms = cms::sign_spec(
        &f.doc,
        &[],
        &SignSpec {
            content: Content::Data(&protected),
            encapsulate: false,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs,
            certificates: CertSpec::Signer,
        },
    )
    .unwrap();
    cms::verify(&cms, Some(&protected)).unwrap();
    bytes[range[1] + 1..range[2] - 1].fill(b'0');
    for (index, byte) in cms.iter().enumerate() {
        bytes[range[1] + 1 + index * 2] = b"0123456789ABCDEF"[(byte >> 4) as usize];
        bytes[range[1] + 2 + index * 2] = b"0123456789ABCDEF"[(byte & 15) as usize];
    }
    f.rejected(&bytes);
}

// Count real allocation work on this test thread only. Other parallel tests
// never enter this measurement. The existing host OperationControl imposes the
// finite work admission; no production quota or allocator is changed.
struct AllocationWork;
thread_local! {
    static ALLOCATION_WORK: std::cell::Cell<(bool,u64)> = const { std::cell::Cell::new((false,0)) };
}
fn record_allocation(bytes: usize) {
    let _ = ALLOCATION_WORK.try_with(|work| {
        let (enabled, total) = work.get();
        if enabled {
            work.set((true, total.saturating_add(bytes as u64)));
        }
    });
}
unsafe impl std::alloc::GlobalAlloc for AllocationWork {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let value = unsafe { std::alloc::System.alloc(layout) };
        if !value.is_null() {
            record_allocation(layout.size());
        }
        value
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let value = unsafe { std::alloc::System.alloc_zeroed(layout) };
        if !value.is_null() {
            record_allocation(layout.size());
        }
        value
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        let value = unsafe { std::alloc::System.realloc(pointer, layout, size) };
        if !value.is_null() {
            record_allocation(size);
        }
        value
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: AllocationWork = AllocationWork;
struct MeasureAllocations;
impl MeasureAllocations {
    fn start() -> Self {
        ALLOCATION_WORK.with(|work| work.set((true, 0)));
        Self
    }
    fn bytes(&self) -> u64 {
        ALLOCATION_WORK.with(|work| work.get().1)
    }
}
impl Drop for MeasureAllocations {
    fn drop(&mut self) {
        ALLOCATION_WORK.with(|work| work.set((false, 0)));
    }
}
struct AllocationAdmission(u64);
impl OperationControl for AllocationAdmission {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if ALLOCATION_WORK.with(|work| work.get().1) > self.0 {
            Err(ProcessingError::MemoryLimit)
        } else {
            Ok(())
        }
    }
}
#[test]
fn multisigner_common_dss_fits_one_shared_allocation_work_admission() {
    let mut f = Fixture::new();
    let (one_t, _) = f.run(None, AdesLevel::T);
    let mut many_t = one_t.clone();
    let mut certificates = vec![f.root.cert.clone(), f.tsa.cert.clone(), f.doc.cert.clone()];
    for serial in [9, 10] {
        let mut spec = TestCertSpec::from_cert(&f.doc.cert);
        spec.serial = vec![0x63, 0x17, serial];
        f.doc.cert = issue_cert(&f.root, spec);
        certificates.push(f.doc.cert.clone());
        many_t = with_tsa(&f, NOW, NOW, |services| {
            let mut s = scope();
            let mut output = services.temporary.stage(&mut s).unwrap();
            ades::sign(
                AdesLevel::T,
                Source::sequential(&mut Cursor::new(&many_t), None),
                &PdfSignProfile::default(),
                &mut f.doc.clone(),
                services,
                &mut output,
                &s,
            )
            .unwrap();
            let mut bytes = Vec::new();
            output.copy_to(&mut bytes).unwrap();
            bytes
        });
    }
    // Genuine issuer-signed renewal certificates, not padding or mock data.
    for serial in 32..80 {
        let mut spec = TestCertSpec::from_cert(&f.doc.cert);
        spec.serial = vec![0x63, 0x17, serial];
        certificates.push(issue_cert(&f.root, spec));
    }
    let extend = |input: &[u8]| {
        with_tsa(&f, NOW, NOW, |services| {
            let configured = AdesServices {
                validation: services.validation,
                host_clock: services.host_clock,
                network: services.network,
                temporary: services.temporary,
                limits: services.limits,
                tsa: services.tsa,
                material: ValidationMaterial {
                    certificates: &certificates,
                    ocsp: &[],
                    crls: services.material.crls,
                },
            };
            let mut s = scope();
            let mut output = services.temporary.stage(&mut s).unwrap();
            ades::extend(
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(input), None),
                &PdfLimits::default(),
                &configured,
                &[SigAlg::RsaSha256],
                &mut output,
                &s,
            )
            .unwrap();
            let mut bytes = Vec::new();
            output.copy_to(&mut bytes).unwrap();
            bytes
        })
    };
    let one = extend(&one_t);
    let many = extend(&many_t);
    f.context(NOW,&f.crl,|services|{
        let verify=|bytes:&[u8],admission:u64|{
            let limits=ResourceLimits::default();
            let mut s=Arc::new(SharedBudget::new(limits.clone()).unwrap()).begin(limits,Arc::new(AllocationAdmission(admission))).unwrap();
            let measured=MeasureAllocations::start();
            let result=ades::verify(AdesLevel::Lta,Source::sequential(&mut Cursor::new(bytes),None),&PdfLimits::default(),services,&[SigAlg::RsaSha256],&mut s);
            let work=measured.bytes();drop(measured);(result,work)
        };
        let (single,single_work)=verify(&one,u64::MAX);let single=single.unwrap();
        assert_eq!(single.verdict,Verdict::Valid);assert_eq!(single.signatures().len(),1);drop(single);
        let (large_control,many_work)=verify(&many,u64::MAX);let large_control=large_control.unwrap();
        assert_eq!(large_control.verdict,Verdict::Valid);assert_eq!(large_control.signatures().len(),3);drop(large_control);
        let admission=single_work.checked_mul(2).unwrap();
        eprintln!("real common certificates={} single_allocation_bytes={single_work} three_allocation_bytes={many_work} shared_admission={admission}",certificates.len());
        let (same_budget_control,_)=verify(&one,admission);assert_eq!(same_budget_control.unwrap().verdict,Verdict::Valid);
        let (shared,_) = verify(&many,admission);
        let shared=shared.expect("three actual source signatures must reuse common evidence within the one shared work admission");
        assert_eq!(shared.verdict,Verdict::Valid);assert_eq!(shared.level(),Some(AdesLevel::Lta));assert_eq!(shared.signatures().len(),3);
    });
}

#[test]
fn yielded_batch_report_retains_original_admission_after_iterator_drop() {
    use oncl_pki::{
        cms::ades::{SnapshotSignature, verify_snapshot_pades},
        io::{FrozenInput, PdfSnapshot, Region, SnapshotEncoding},
    };
    use std::sync::Mutex;
    let f = Fixture::new();
    let (bytes, _) = f.run(None, AdesLevel::T);
    let doc = lopdf::Document::load_mem(&bytes).unwrap();
    let dictionary = doc
        .objects
        .values()
        .find_map(|value| {
            value.as_dict().ok().filter(|dict| {
                dict.get(b"Type")
                    .is_ok_and(|v| v.as_name().is_ok_and(|n| n == b"Sig"))
            })
        })
        .unwrap();
    let range: Vec<_> = dictionary
        .get(b"ByteRange")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap() as u64)
        .collect();
    f.context(NOW, &f.crl, |services| {
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let report = {
            let mut s = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
            let mut frozen = FrozenInput::capture(
                Source::sequential(&mut Cursor::new(&bytes), None),
                services.temporary,
                &mut s,
            )
            .unwrap();
            let mut view = PdfSnapshot::input(&mut frozen, &s).unwrap();
            let metadata = view
                .derive_region(
                    Region {
                        offset: range[1],
                        len: range[2] - range[1],
                    },
                    &s,
                    SnapshotEncoding::PdfByteString,
                )
                .unwrap();
            let snapshot = Mutex::new(view);
            let mut reports = verify_snapshot_pades(
                AdesLevel::T,
                &[SnapshotSignature {
                    metadata: &metadata,
                    regions: [
                        Region {
                            offset: range[0],
                            len: range[1],
                        },
                        Region {
                            offset: range[2],
                            len: range[3],
                        },
                    ],
                }],
                &snapshot,
                &[],
                &[],
                services,
                &[SigAlg::RsaSha256],
                &s,
            )
            .unwrap()
            .into_iter();
            let report = reports.next().unwrap();
            assert!(reports.next().is_none());
            drop(reports);
            report
        };
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(report.level(), Some(AdesLevel::T));
        assert!(matches!(
            budget.begin(limits.clone(), Arc::new(Control)),
            Err(ProcessingError::CapacityExceeded)
        ));
        drop(report);
        assert!(budget.begin(limits, Arc::new(Control)).is_ok());
    });
}

struct ReplyHostClock {
    tsa: MockTsa,
    now: Arc<std::sync::Mutex<OffsetDateTime>>,
    post_reply: OffsetDateTime,
}
impl oncl_pki::http::HttpTransport for ReplyHostClock {
    fn send(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        let reply = oncl_pki::http::HttpTransport::send(&self.tsa, request)?;
        *self.now.lock().unwrap() = self.post_reply;
        Ok(reply)
    }
}
#[test]
fn document_timestamp_uses_post_reply_host_time_without_future_or_backwards_grace() {
    let f = Fixture::new();
    let (b, _) = f.run(None, AdesLevel::B);
    let checked = NOW + time::Duration::seconds(2);
    for (started, issued, post_reply, valid) in [
        (NOW, NOW + time::Duration::SECOND, checked, true),
        (NOW, checked + time::Duration::SECOND, checked, false),
        (checked, NOW, NOW, false),
    ] {
        f.context(NOW, &f.crl, |base| {
            let now = Arc::new(std::sync::Mutex::new(started));
            let clock = || *now.lock().unwrap();
            let http = ReplyHostClock {
                tsa: MockTsa::new(f.tsa.clone()).with_gen_time(issued),
                now: now.clone(),
                post_reply,
            };
            let validation = ValidationContext {
                http: &http,
                ..*base.validation
            };
            let mut profile = TsaProfile::kalkan_default();
            profile.url = URL.into();
            profile.method = TsaMethod::Post;
            let mut tsa = TsaSpec::from(profile);
            tsa.check_skew = None;
            let services = AdesServices {
                validation: &validation,
                host_clock: Some(&clock),
                network: base.network,
                temporary: base.temporary,
                limits: base.limits,
                tsa: Some(&tsa),
                material: ValidationMaterial {
                    certificates: base.material.certificates,
                    ocsp: base.material.ocsp,
                    crls: base.material.crls,
                },
            };
            let mut s = scope();
            let mut output = services.temporary.stage(&mut s).unwrap();
            let result = ades::extend(
                AdesLevel::T,
                Source::sequential(&mut Cursor::new(&b), None),
                &PdfLimits::default(),
                &services,
                &[SigAlg::RsaSha256],
                &mut output,
                &s,
            );
            if valid {
                let report = result.unwrap();
                assert_eq!(report.verdict, Verdict::Valid);
                let signer = &report.signatures()[0].validation;
                assert_eq!(signer.checked_at, checked);
                assert_eq!(signer.signers[0].proof_time.as_ref().unwrap().at(), issued);
            } else {
                assert!(matches!(
                    result,
                    Err(oncl_pdf::PdfError::Ades(
                        oncl_pki::cms::ades::AdesError::Timestamp(
                            oncl_pki::tsp::TspError::ClockSkew
                        )
                    ))
                ));
                assert!(output.copy_to(&mut Vec::new()).is_err());
            }
        });
    }
}
#[test]
fn every_source_cms_uses_one_fresh_final_host_instant() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut f = Fixture::new();
    let (first, _) = f.run(None, AdesLevel::B);
    let mut spec = TestCertSpec::from_cert(&f.doc.cert);
    spec.serial = vec![0x63, 0x17, 99];
    f.doc.cert = issue_cert(&f.root, spec);
    let second = f.context(NOW, &f.crl, |services| {
        let mut s = scope();
        let mut output = services.temporary.stage(&mut s).unwrap();
        ades::sign(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(&first), None),
            &PdfSignProfile::default(),
            &mut f.doc.clone(),
            services,
            &mut output,
            &s,
        )
        .unwrap();
        let mut bytes = Vec::new();
        output.copy_to(&mut bytes).unwrap();
        bytes
    });
    f.context(NOW, &f.crl, |base| {
        let samples = AtomicUsize::new(0);
        let clock = || {
            let sample = samples.fetch_add(1, Ordering::SeqCst) + 1;
            NOW + time::Duration::seconds(sample as i64)
        };
        let services = AdesServices {
            validation: base.validation,
            host_clock: Some(&clock),
            network: base.network,
            temporary: base.temporary,
            limits: base.limits,
            tsa: base.tsa,
            material: ValidationMaterial {
                certificates: base.material.certificates,
                ocsp: base.material.ocsp,
                crls: base.material.crls,
            },
        };
        let report = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(&second), None),
            &PdfLimits::default(),
            &services,
            &[SigAlg::RsaSha256],
            &mut scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(report.signatures().len(), 2);
        assert_eq!(samples.load(Ordering::SeqCst), 1);
        for signature in report.signatures() {
            assert_eq!(
                signature.validation.checked_at,
                NOW + time::Duration::SECOND
            );
        }
    });
}

#[test]
fn final_pades_host_clock_must_not_move_backwards_from_initial_host_context() {
    let f = Fixture::new();
    let (bytes, _) = f.run(None, AdesLevel::B);
    f.context(NOW, &f.crl, |base| {
        let clock = || NOW - time::Duration::SECOND;
        let services = AdesServices {
            validation: base.validation,
            host_clock: Some(&clock),
            network: base.network,
            temporary: base.temporary,
            limits: base.limits,
            tsa: base.tsa,
            material: ValidationMaterial {
                certificates: base.material.certificates,
                ocsp: base.material.ocsp,
                crls: base.material.crls,
            },
        };
        let result = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(&bytes), None),
            &PdfLimits::default(),
            &services,
            &[SigAlg::RsaSha256],
            &mut scope(),
        );
        assert!(matches!(
            result,
            Err(oncl_pdf::PdfError::Ades(
                oncl_pki::cms::ades::AdesError::Timestamp(oncl_pki::tsp::TspError::ClockSkew)
            ))
        ));
    });
}

const LEVELS: [AdesLevel; 4] = [AdesLevel::B, AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta];

/// The second signer: another certificate from the same root, long lived.
fn second_signer(f: &Fixture) -> KeyEntry {
    let mut second = f.doc.clone();
    let mut spec = TestCertSpec::from_cert(&f.doc.cert);
    spec.serial = vec![0x63, 0x17, 9];
    spec.validity = *entry("user-rsa-sign").cert.tbs_certificate().validity();
    second.cert = issue_cert(&f.root, spec);
    second
}
/// One attempt to sign at `level` onto `old`, with every observable side effect.
struct Onto {
    /// Private-key uses of the new signer.
    calls: usize,
    /// TimeStampReq's the TSA received.
    tsa_requests: usize,
    /// Whether the staged output can be read back afterwards.
    output_readable: bool,
    result: Result<(Vec<u8>, ades::PadesReport), oncl_pdf::PdfError>,
}
fn run_onto(f: &Fixture, old: &[u8], level: AdesLevel) -> Onto {
    let mut signer = CountSigner {
        key: second_signer(f),
        calls: 0,
    };
    let (tsa_requests, output_readable, result) = with_tsa_counted(f, NOW, NOW, |services, tsa| {
        let mut s = scope();
        let mut output = services.temporary.stage(&mut s).unwrap();
        let signed = ades::sign(
            level,
            Source::sequential(&mut Cursor::new(old), None),
            &PdfSignProfile::default(),
            &mut signer,
            services,
            &mut output,
            &s,
        );
        let mut bytes = Vec::new();
        let readable = output.copy_to(&mut bytes).is_ok();
        let result = signed.and_then(|_| {
            assert!(bytes.starts_with(old), "previous revisions are untouched");
            let report = ades::verify(
                AdesLevel::B,
                Source::sequential(&mut Cursor::new(&bytes), None),
                &PdfLimits::default(),
                services,
                &[SigAlg::RsaSha256],
                &mut s,
            )?;
            Ok((bytes, report))
        });
        (tsa.requests().len(), readable, result)
    });
    Onto {
        calls: signer.calls,
        tsa_requests,
        output_readable,
        result,
    }
}
#[test]
fn signing_onto_an_already_signed_pdf_succeeds_at_every_level() {
    let f = Fixture::new();
    for prior in LEVELS {
        let (old, _) = f.run(None, prior);
        for level in LEVELS {
            let label = format!("{prior:?} then {level:?}");
            let onto = run_onto(&f, &old, level);
            let (_, report) = onto.result.unwrap_or_else(|e| panic!("{label}: {e:?}"));
            assert!(onto.output_readable, "{label}");
            // The provider signs exactly once, for the new signature only.
            assert_eq!(onto.calls, 1, "{label}");
            // TSA requests: the new signature's own timestamp (T and above), one
            // document timestamp when an old B signature has to be brought to T before
            // the DSS, and one closing document timestamp for LTA.
            let timestamps = usize::from(level >= AdesLevel::T)
                + usize::from(level >= AdesLevel::Lt && prior == AdesLevel::B)
                + usize::from(level == AdesLevel::Lta);
            assert_eq!(onto.tsa_requests, timestamps, "{label}");
            assert_eq!(report.signatures().len(), 2, "{label}");
            assert_eq!(report.verdict, Verdict::Valid, "{label}");
            // `signature_levels` are ACHIEVED levels. An old signature is only elevated
            // by the evidence appended for LT/LTA (DSS and document timestamps), never
            // relabelled; the new one reaches at least the request. The aggregate is the
            // minimum achieved level, not the requested one.
            let old_expected = match level {
                AdesLevel::B | AdesLevel::T => prior,
                AdesLevel::Lt => AdesLevel::Lt,
                AdesLevel::Lta => AdesLevel::Lta,
            };
            // A new T signature in a file that already holds DSS material is proven
            // against it, so it achieves LT there (above the request, never below it).
            let new_expected = if level == AdesLevel::T && prior >= AdesLevel::Lt {
                AdesLevel::Lt
            } else {
                level
            };
            assert_eq!(
                report.signature_levels(),
                [Some(old_expected), Some(new_expected)],
                "{label}"
            );
            assert_eq!(
                report.level(),
                Some(old_expected.min(new_expected)),
                "{label}"
            );
        }
    }
}
/// Signing onto `bytes` must be refused BEFORE any private use: a typed pre-key error
/// (never `AfterKeyUse`), no provider call, no TSA request, no readable output.
fn assert_refused_before_key_use(f: &Fixture, bytes: &[u8], what: &str) {
    for level in LEVELS {
        let onto = run_onto(f, bytes, level);
        let error = onto
            .result
            .err()
            .unwrap_or_else(|| panic!("{what} {level:?}"));
        assert!(
            !matches!(
                error,
                oncl_pdf::PdfError::Ades(oncl_pki::cms::ades::AdesError::AfterKeyUse { .. })
            ),
            "{what} {level:?}: {error:?}"
        );
        assert_eq!(onto.calls, 0, "{what} {level:?}: no private use");
        assert_eq!(onto.tsa_requests, 0, "{what} {level:?}: no TSA request");
        assert!(!onto.output_readable, "{what} {level:?}: no output");
    }
}
fn flip_hex(byte: u8) -> u8 {
    if byte == b'0' { b'1' } else { b'0' }
}
#[test]
fn a_bad_present_signature_blocks_signing_before_any_key_use() {
    // A revoked old signer.
    let mut f = Fixture::new();
    let (old, _) = f.run(None, AdesLevel::B);
    f.crl = MockCrl::new(f.root.clone())
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .revoke(
            f.doc.cert.tbs_certificate().serial_number().as_bytes(),
            NOW - time::Duration::HOUR,
        )
        .der();
    assert_refused_before_key_use(&f, &old, "revoked old signer");
}
#[test]
fn a_tampered_old_signature_timestamp_or_dss_blocks_signing_before_any_key_use() {
    let f = Fixture::new();
    // The control: the same untampered files accept a new signature at every level.
    for prior in [AdesLevel::B, AdesLevel::T, AdesLevel::Lta] {
        let (old, _) = f.run(None, prior);
        assert!(
            run_onto(&f, &old, AdesLevel::Lta).result.is_ok(),
            "{prior:?}"
        );
    }
    let valid = |bytes: &[u8]| {
        f.inspect(bytes, AdesLevel::B, NOW, &f.crl)
            .is_ok_and(|report| report.verdict == Verdict::Valid)
    };
    // (1) Signed document bytes of an old B signature (inside its ByteRange) changed.
    let (b, _) = f.run(None, AdesLevel::B);
    let mut content = b.clone();
    let at = content
        .windows(6)
        .position(|part| part == b"endobj")
        .unwrap();
    content[at + 5] = b'k';
    assert!(!valid(&content));
    assert_refused_before_key_use(&f, &content, "tampered signed content");
    // (2) The old signature value itself changed.
    let (t, _) = f.run(None, AdesLevel::T);
    let contents = t
        .windows(b"/Contents <".len())
        .position(|part| part == b"/Contents <")
        .unwrap()
        + b"/Contents <".len();
    let end = contents + t[contents..].iter().position(|b| *b == b'>').unwrap();
    let last = contents + t[contents..end].iter().rposition(|b| *b != b'0').unwrap();
    // (3) The signature timestamp token of an old T signature: its tail is the TSA's
    // own signature value.
    let mut token = t.clone();
    token[last - 40] = flip_hex(token[last - 40]);
    assert!(!valid(&token));
    assert_refused_before_key_use(&f, &token, "bad old timestamp token");
    let mut signature = t.clone();
    let offset = signature[contents..end]
        .windows(2)
        .position(|part| part == b"30")
        .unwrap();
    // The first CMS bytes are structure: any change fails the old signature.
    signature[contents + offset + 2] = flip_hex(signature[contents + offset + 2]);
    assert!(!valid(&signature));
    assert_refused_before_key_use(&f, &signature, "changed old CMS");
    // (4) A bad entry in the DSS of an old LTA file.
    let (lta, _) = f.run(None, AdesLevel::Lta);
    let mut dss = lta.clone();
    let offset = dss
        .windows(f.crl.len())
        .position(|part| part == f.crl)
        .unwrap();
    dss[offset + f.crl.len() - 1] ^= 1;
    assert!(!valid(&dss));
    assert_refused_before_key_use(&f, &dss, "altered DSS entry");
    // (5) The closing document timestamp of the old LTA file.
    let mut closing = lta.clone();
    let start = closing
        .windows(b"/ETSI.RFC3161".len())
        .rposition(|part| part == b"/ETSI.RFC3161")
        .unwrap();
    let gap = start
        + closing[start..]
            .windows(11)
            .position(|part| part == b"/Contents <")
            .unwrap()
        + 11;
    closing[gap + 100] ^= 1;
    assert!(!valid(&closing));
    assert_refused_before_key_use(&f, &closing, "altered document timestamp");
}
#[test]
fn a_revision_appended_over_signed_ranges_is_rejected_by_the_whole_file_checks() {
    let f = Fixture::new();
    let (old, _) = f.run(None, AdesLevel::B);
    let (two, _) = run_onto(&f, &old, AdesLevel::B).result.unwrap();
    let doc = lopdf::Document::load_mem(&two).unwrap();
    let page = *doc.get_pages().values().next().unwrap();
    let mut page_value = doc.get_object(page).unwrap().as_dict().unwrap().clone();
    page_value.set("MediaBox", vec![0.into(), 0.into(), 1.into(), 1.into()]);
    let root = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let mut catalog = doc.get_object(root).unwrap().as_dict().unwrap().clone();
    catalog.set("Perms", lopdf::Object::Name(b"Forged".to_vec()));
    let forgeries = [
        (
            "page changed under both signatures",
            vec![(page, lopdf::Object::Dictionary(page_value))],
        ),
        (
            "catalog permissions injected",
            vec![(root, lopdf::Object::Dictionary(catalog))],
        ),
    ];
    for (what, objects) in forgeries {
        let forged = append_objects(&two, objects);
        // Neither the verifier nor a later signing operation accepts it.
        assert!(
            !f.inspect(&forged, AdesLevel::B, NOW, &f.crl)
                .is_ok_and(|report| report.verdict == Verdict::Valid),
            "{what}"
        );
        assert_refused_before_key_use(&f, &forged, what);
    }
}
/// Moves the host clock when the TSA replies, i.e. after the private key was used.
struct JumpAfterReply {
    tsa: MockTsa,
    now: Arc<std::sync::Mutex<OffsetDateTime>>,
    after: OffsetDateTime,
}
impl oncl_pki::http::HttpTransport for JumpAfterReply {
    fn send(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        let reply = oncl_pki::http::HttpTransport::send(&self.tsa, request)?;
        *self.now.lock().unwrap() = self.after;
        Ok(reply)
    }
}
#[test]
fn final_check_rejects_an_old_signature_that_stopped_validating_after_key_use() {
    use der::asn1::UtcTime;
    let mut f = Fixture::new();
    // The old signer's certificate ends 30 minutes after NOW.
    let mut spec = TestCertSpec::from_cert(&f.doc.cert);
    spec.validity.not_after = x509_cert::time::Time::UtcTime(
        UtcTime::from_unix_duration(std::time::Duration::from_secs(
            (NOW + time::Duration::minutes(30)).unix_timestamp() as u64,
        ))
        .unwrap(),
    );
    f.doc.cert = issue_cert(&f.root, spec);
    let (old, _) = f.run(None, AdesLevel::B);
    for (after, expect_ok) in [
        // Control: the clock moves on, the old certificate is still valid.
        (NOW + time::Duration::minutes(10), true),
        // Past the old certificate's end, before the CRL's nextUpdate.
        (NOW + time::Duration::minutes(40), false),
    ] {
        let mut signer = CountSigner {
            key: second_signer(&f),
            calls: 0,
        };
        let (result, readable) = f.context(NOW, &f.crl, |base| {
            let now = Arc::new(std::sync::Mutex::new(NOW));
            let clock = || *now.lock().unwrap();
            let http = JumpAfterReply {
                tsa: MockTsa::new(f.tsa.clone()).with_gen_time(NOW),
                now: now.clone(),
                after,
            };
            let validation = ValidationContext {
                http: &http,
                ..*base.validation
            };
            let mut profile = TsaProfile::kalkan_default();
            profile.url = URL.into();
            profile.method = TsaMethod::Post;
            let mut tsa = TsaSpec::from(profile);
            tsa.check_skew = None;
            let services = AdesServices {
                validation: &validation,
                host_clock: Some(&clock),
                network: base.network,
                temporary: base.temporary,
                limits: base.limits,
                tsa: Some(&tsa),
                material: ValidationMaterial {
                    certificates: base.material.certificates,
                    ocsp: base.material.ocsp,
                    crls: base.material.crls,
                },
            };
            let mut s = scope();
            let mut output = services.temporary.stage(&mut s).unwrap();
            let result = ades::sign(
                AdesLevel::T,
                Source::sequential(&mut Cursor::new(&old), None),
                &PdfSignProfile::default(),
                &mut signer,
                &services,
                &mut output,
                &s,
            );
            (result, output.copy_to(&mut Vec::new()).is_ok())
        });
        assert_eq!(signer.calls, 1, "{after}: the key was used once");
        if expect_ok {
            result.unwrap();
            assert!(readable);
        } else {
            // Fail closed and honest: no output, and the key use is reported.
            assert!(
                matches!(
                    result,
                    Err(oncl_pdf::PdfError::Ades(
                        oncl_pki::cms::ades::AdesError::AfterKeyUse {
                            applied: oncl_pki::key::AppliedState::Applied,
                            ..
                        }
                    ))
                ),
                "{result:?}"
            );
            assert!(!readable);
        }
    }
}
