//! C03 real signature contract; no token-presence level assertions.
#![cfg(feature = "testing")]
use oncl_pki::{
    cms::{
        ades,
        stream::{CmsSignRequest, CmsSignServices},
    },
    evidence::AdesLevel,
    io::{Source, TemporaryStore},
    pkcs12::load,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use std::{io::Cursor, sync::Arc};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
#[test]
fn baseline_preserves_real_signature_and_content() {
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let mut key = load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let limits = ResourceLimits::default();
    let scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap();
    let mut output = Vec::new();
    ades::sign(
        &CmsSignRequest::create(true),
        AdesLevel::B,
        Source::sequential(&mut Cursor::new(b"C03 actual signed content"), None),
        None,
        &mut [&mut key],
        &CmsSignServices::new(None, Some(&store)),
        None,
        &mut output,
        &scope,
    )
    .unwrap();
    let signers = oncl_pki::cms::verify(&output, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert!(oncl_pki::cms::verify(&output, Some(b"irrelevant detached override")).is_ok());
    let mut altered = output.clone();
    let position = altered
        .windows(25)
        .position(|part| part == b"C03 actual signed content")
        .unwrap();
    altered[position] ^= 1;
    assert!(oncl_pki::cms::verify(&altered, None).is_err());
}

mod cades {
    use super::*;
    use der::asn1::{AnyRef, UtcTime};
    use der::{Decode, Encode, Reader as _, SliceReader};
    use oncl_pki::{
        cert::Certificate,
        crl::MockCrl,
        evidence::EvidenceLimits,
        http::HttpTransport,
        key::{PrivateKey, SigAlg},
        pkcs12::KeyEntry,
        pkix::CaSet,
        testing::{TestCertSpec, issue_cert},
        tsp::{MockTsa, TsaMethod, TsaProfile, TsaSpec},
        validation::{NetworkPolicy, TimeBasis, ValidationContext, ValidationPolicy, Verdict},
    };
    use std::time::Duration;
    use time::{OffsetDateTime, macros::datetime};
    use x509_cert::time::Time;
    const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
    const DATA: &[u8] = b"C03 real RSA content for baseline archival verification";
    const URL: &str = "http://127.0.0.1:47819/tsa";
    fn entry(name: &str) -> KeyEntry {
        let value = oncl_testkit::synthetic(name);
        load(&oncl_testkit::read(value.path), &value.password)
            .unwrap()
            .remove(0)
    }
    fn time(at: OffsetDateTime) -> Time {
        Time::UtcTime(
            UtcTime::from_unix_duration(Duration::from_secs(at.unix_timestamp() as u64)).unwrap(),
        )
    }
    fn strip(spec: &mut TestCertSpec) {
        spec.extensions.retain(|extension| {
            !matches!(
                extension.extn_id.to_string().as_str(),
                "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        });
    }
    pub struct Fixture {
        pub doc: KeyEntry,
        pub tsa: KeyEntry,
        pub root: KeyEntry,
        pub anchors: CaSet,
        pub crl: Vec<u8>,
    }
    impl Fixture {
        pub fn new() -> Self {
            let mut root = entry("user-rsa-sign");
            root.key = PrivateKey::from_pkcs8_der(
                include_bytes!("../../../fixtures/openssl/rsa.pk8.der"),
                None,
            )
            .unwrap();
            let mut spec = TestCertSpec::from_cert(&entry("root-gost2015.key").cert);
            spec.subject = root.cert.tbs_certificate().subject().clone();
            spec.public_key = root.key.public_key().to_spki();
            spec.serial = vec![0x63, 0x03, 1];
            strip(&mut spec);
            root.cert = issue_cert(&root, spec);
            let mut doc = entry("user-rsa-sign");
            let mut spec = TestCertSpec::from_cert(&doc.cert);
            strip(&mut spec);
            spec.serial = vec![0x63, 0x03, 2];
            doc.cert = issue_cert(&root, spec);
            let mut tsa = doc.clone();
            let mut spec = TestCertSpec::from_cert(&entry("tsa-gost2015").cert);
            spec.public_key = tsa.key.public_key().to_spki();
            spec.serial = vec![0x63, 0x03, 3];
            strip(&mut spec);
            tsa.cert = issue_cert(&root, spec);
            let crl = MockCrl::new(root.clone())
                .with_this_update(NOW - time::Duration::MINUTE)
                .next_update(Some(NOW + time::Duration::HOUR))
                .der();
            Self {
                anchors: CaSet::new(vec![root.cert.clone()]),
                doc,
                tsa,
                root,
                crl,
            }
        }
    }
    fn limits() -> ResourceLimits {
        ResourceLimits {
            memory_bytes: 256 << 20,
            metadata_bytes: 32 << 20,
            temp_bytes: 256 << 20,
            ..ResourceLimits::default()
        }
    }
    fn scope() -> oncl_pki::resource::ResourceScope {
        let limits = limits();
        Arc::new(SharedBudget::new(limits.clone()).unwrap())
            .begin(limits, Arc::new(Control))
            .unwrap()
    }
    fn evidence_limits() -> EvidenceLimits {
        EvidenceLimits {
            max_items: 64,
            max_bytes: 8 << 20,
            max_item_bytes: 1 << 20,
            max_crl_bytes: 8 << 20,
            max_crl_item_bytes: 1 << 20,
            max_total_bytes: 8 << 20,
            max_chain_len: 8,
            max_proofs: 8,
            max_coverage_parts: 1024,
            max_coverage_bytes: 10_737_418_240,
        }
    }
    fn profile() -> TsaSpec {
        let mut profile = TsaProfile::kalkan_default();
        profile.url = URL.into();
        profile.method = TsaMethod::Post;
        let mut spec = TsaSpec::from(profile);
        spec.check_skew = None;
        spec
    }
    fn children(bytes: &[u8]) -> Vec<Vec<u8>> {
        let value = AnyRef::from_der(bytes).unwrap();
        let mut reader = SliceReader::new(value.value()).unwrap();
        let mut fields = vec![];
        while !reader.is_finished() {
            fields.push(reader.tlv_bytes().unwrap().to_vec());
        }
        fields
    }
    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if bytes.len() < 128 {
            result.push(bytes.len() as u8);
        } else {
            let length = bytes.len().to_be_bytes();
            let length = &length[length.iter().position(|byte| *byte != 0).unwrap()..];
            result.push(0x80 | length.len() as u8);
            result.extend_from_slice(length);
        }
        result.extend_from_slice(bytes);
        result
    }
    fn signature_fields(bytes: &[u8]) -> Vec<Vec<u8>> {
        let ci = children(bytes);
        let explicit = children(&ci[1]);
        let sd = children(&explicit[0]);
        let signers = children(sd.last().unwrap());
        children(&signers[0])[..6].to_vec()
    }
    fn baseline(
        f: &Fixture,
        attached: bool,
        now: OffsetDateTime,
        store: &TemporaryStore,
    ) -> Vec<u8> {
        // Independent producer uses the established legacy encoder with real
        // mandatory baseline signed attrs; adding CRL does not change them.
        let mut bytes = oncl_pki::cms::sign(
            &f.doc,
            DATA,
            &oncl_pki::cms::SignOptions {
                encapsulate: attached,
                digested: false,
                signing_time: now,
            },
        )
        .unwrap();
        let ci = children(&bytes);
        let explicit = children(&ci[1]);
        let mut sd = children(&explicit[0]);
        let cert_index = sd.iter().position(|field| field[0] == 0xa0).unwrap();
        let mut certs = AnyRef::from_der(&sd[cert_index]).unwrap().value().to_vec();
        certs.extend_from_slice(&f.root.cert.to_der().unwrap());
        certs.extend_from_slice(&f.tsa.cert.to_der().unwrap());
        sd[cert_index] = tlv(0xa0, &certs);
        sd.insert(sd.len() - 1, tlv(0xa1, &f.crl));
        bytes = tlv(
            0x30,
            &[ci[0].clone(), tlv(0xa0, &tlv(0x30, &sd.concat()))].concat(),
        );
        let _ = store;
        bytes
    }
    fn services<'a>(
        context: &'a ValidationContext<'a>,
        network: &'a NetworkPolicy,
        store: &'a TemporaryStore,
        tsa: &'a TsaSpec,
        certs: &'a [Certificate],
        crls: &'a [&'a [u8]],
    ) -> ades::AdesServices<'a> {
        ades::AdesServices {
            validation: context,
            network,
            temporary: store,
            limits: evidence_limits(),
            tsa: Some(tsa),
            material: ades::ValidationMaterial {
                certificates: certs,
                ocsp: &[],
                crls,
            },
            host_clock: None,
        }
    }
    fn run(
        f: &Fixture,
        input: &[u8],
        attached: bool,
        target: AdesLevel,
        now: OffsetDateTime,
    ) -> (Vec<u8>, ades::AdesReport) {
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(now);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let mut output = Vec::new();
        let mut data = Cursor::new(DATA);
        let report = ades::extend(
            target,
            Source::sequential(&mut Cursor::new(input), Some(input.len() as u64)),
            (!attached).then(|| Source::sequential(&mut data, Some(DATA.len() as u64))),
            &services,
            &[SigAlg::RsaSha256],
            &mut output,
            &scope(),
        )
        .unwrap();
        (output, report)
    }
    #[test]
    fn extend_lt_lta_without_resigning_content() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        for attached in [true, false] {
            let baseline = baseline(&f, attached, NOW - time::Duration::MINUTE, &store);
            let before = signature_fields(&baseline);
            let (lt, report) = run(&f, &baseline, attached, AdesLevel::Lt, NOW);
            assert_eq!(report.verdict, Verdict::Valid);
            assert_eq!(report.level(), Some(AdesLevel::Lt));
            assert_eq!(signature_fields(&lt), before);
            assert!(report.reports()[0].signers[0].proof_time.is_some());
            let (lta, report) = run(&f, &lt, attached, AdesLevel::Lta, NOW);
            assert_eq!(report.verdict, Verdict::Valid);
            assert_eq!(report.level(), Some(AdesLevel::Lta));
            assert_eq!(signature_fields(&lta), before);
            assert_eq!(
                oncl_pki::cms::verify(&lta, (!attached).then_some(DATA))
                    .unwrap()
                    .len(),
                1
            );
        }
    }
    #[test]
    fn archive_timestamp_tamper() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let baseline = baseline(&f, true, NOW, &store);
        let (mut lta, _) = run(&f, &baseline, true, AdesLevel::Lta, NOW);
        // Mutate a referenced hash in the actual ATSHashIndexV3 (TSA signature
        // alone still verifies): this is completed Invalid, not execution error.
        let position = lta.len() - 10;
        lta[position] ^= 1;
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let result = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&lta), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        );
        let report = result.unwrap();
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.level(), None);
    }
    #[test]
    fn expired_now_valid_at_proven_time() {
        let mut f = Fixture::new();
        let mut spec = TestCertSpec::from_cert(&f.doc.cert);
        spec.validity.not_after = time(NOW - time::Duration::SECOND);
        strip(&mut spec);
        f.doc.cert = issue_cert(&f.root, spec);
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let before = NOW - time::Duration::MINUTE;
        let baseline = baseline(&f, true, before, &store);
        let (lt, _) = run(&f, &baseline, true, AdesLevel::Lt, before);
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let report = ades::verify(
            AdesLevel::Lt,
            Source::sequential(&mut Cursor::new(lt), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(
            report.reports()[0].signers[0].time_basis,
            TimeBasis::VerifiedTimestamp(before)
        );
        assert_eq!(
            report.reports()[0].signers[0]
                .proof_time
                .as_ref()
                .unwrap()
                .at(),
            before
        );
    }
    #[test]
    fn private_create_attached_and_detached_lta_has_two_real_signers() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        for attached in [true, false] {
            let mut first = f.doc.clone();
            let mut second = f.doc.clone();
            let mut spec = TestCertSpec::from_cert(&second.cert);
            spec.serial = vec![0x63, 3, 4];
            strip(&mut spec);
            second.cert = issue_cert(&f.root, spec);
            let mut output = Vec::new();
            ades::sign(
                &CmsSignRequest::create(attached),
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(DATA), None),
                None,
                &mut [&mut first, &mut second],
                &CmsSignServices::new(None, Some(&store)),
                Some(&services),
                &mut output,
                &scope(),
            )
            .unwrap();
            assert_eq!(
                oncl_pki::cms::verify(&output, (!attached).then_some(DATA))
                    .unwrap()
                    .len(),
                2
            );
            let mut detached = Cursor::new(DATA);
            let report = ades::verify(
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(output), None),
                (!attached).then(|| Source::sequential(&mut detached, Some(DATA.len() as u64))),
                &services,
                &[SigAlg::RsaSha256],
                &scope(),
            )
            .unwrap();
            assert_eq!(report.level(), Some(AdesLevel::Lta));
            assert_eq!(report.reports().len(), 2);
        }
    }
    #[test]
    fn cades_add_rejects_bad_prior_archive_before_new_private_application() {
        use oncl_pki::{
            digest::DigestValue,
            key::{DigestSigner, KeyError},
        };
        struct Spy {
            key: KeyEntry,
            calls: usize,
        }
        impl DigestSigner for Spy {
            fn certificate(&self) -> &Certificate {
                &self.key.cert
            }
            fn algorithm(&self) -> SigAlg {
                SigAlg::RsaSha256
            }
            fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
                self.calls += 1;
                DigestSigner::sign_digest(&mut self.key, digest)
            }
        }
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (mut source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let position = source.len() - 10;
        source[position] ^= 1;
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let mut key = f.doc.clone();
        let mut spec = TestCertSpec::from_cert(&key.cert);
        spec.serial = vec![0x63, 3, 5];
        strip(&mut spec);
        key.cert = issue_cert(&f.root, spec);
        let mut signer = Spy { key, calls: 0 };
        let mut output = Vec::new();
        let result = ades::sign(
            &CmsSignRequest::add(),
            AdesLevel::T,
            Source::sequential(&mut Cursor::new(source), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(Some(&context), Some(&store)),
            Some(&services),
            &mut output,
            &scope(),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("all original CAdES signatures and proofs must validate before Add")
        );
        assert_eq!(
            signer.calls, 0,
            "known invalid archive must be rejected before applying the new key"
        );
        assert!(output.is_empty());
    }
    #[test]
    fn cades_add_preserves_old_lta_and_reports_minimum_verified_level() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let before = signature_fields(&source);
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let mut signer = f.doc.clone();
        let mut spec = TestCertSpec::from_cert(&signer.cert);
        spec.serial = vec![0x63, 3, 6];
        strip(&mut spec);
        signer.cert = issue_cert(&f.root, spec);
        let mut output = Vec::new();
        ades::sign(
            &CmsSignRequest::add(),
            AdesLevel::T,
            Source::sequential(&mut Cursor::new(source), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(Some(&context), Some(&store)),
            Some(&services),
            &mut output,
            &scope(),
        )
        .unwrap();
        let ci = children(&output);
        let explicit = children(&ci[1]);
        let sd = children(&explicit[0]);
        assert!(
            children(sd.last().unwrap())
                .iter()
                .any(|signer| children(signer)[..6] == before)
        );
        let report = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(output), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        let mut levels = report
            .reports()
            .iter()
            .map(|report| report.signers[0].ades_level.unwrap())
            .collect::<Vec<_>>();
        levels.sort();
        assert_eq!(levels, [AdesLevel::Lt, AdesLevel::Lta]);
        assert_eq!(report.level(), Some(AdesLevel::Lt));
    }
    #[test]
    fn renewal_preserves_prior_proofs_and_rejects_backdating() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let (renewed, report) = run(
            &f,
            &source,
            true,
            AdesLevel::Lta,
            NOW + time::Duration::MINUTE,
        );
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(signature_fields(&source), signature_fields(&renewed));
        let old_ci = children(&source);
        let old_sd = children(&children(&old_ci[1])[0]);
        let new_ci = children(&renewed);
        let new_sd = children(&children(&new_ci[1])[0]);
        let old_attrs = children(&children(&children(old_sd.last().unwrap())[0])[6]);
        let new_attrs = children(&children(&children(new_sd.last().unwrap())[0])[6]);
        assert!(
            old_attrs
                .iter()
                .all(|attribute| new_attrs.contains(attribute))
        );
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW - time::Duration::MINUTE);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let mut output = Vec::new();
        let error = ades::extend(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&source), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &mut output,
            &scope(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("extended CAdES did not validate")
        );
        assert!(output.is_empty());
    }
    #[test]
    fn rfc5940_ocsp_choice_sets_signed_data_version_five() {
        use oncl_pki::{
            http::{GetOptions, HttpRequest},
            ocsp::{self, MockOcsp},
        };
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let request = ocsp::request_der(&f.doc.cert, &f.root.cert);
        let response = MockOcsp::new(f.root.clone())
            .with_now(NOW)
            .send(&HttpRequest::post(
                URL,
                Some("application/ocsp-request"),
                &request,
                GetOptions::default(),
            ))
            .unwrap()
            .body;
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let ocsp = [response.as_slice()];
        let mut services = services(&context, &network, &store, &profile, &certs, &crls);
        services.material.ocsp = &ocsp;
        let mut output = Vec::new();
        ades::extend(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(baseline(&f, true, NOW, &store)), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &mut output,
            &scope(),
        )
        .unwrap();
        let ci = children(&output);
        let sd = children(&children(&ci[1])[0]);
        assert_eq!(sd[0], [2, 1, 5]);
        assert!(
            children(sd.iter().find(|value| value[0] == 0xa1).unwrap())
                .iter()
                .any(|value| value[0] == 0xa1)
        );
        let report = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(output), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        let mut wrong_version = sd;
        wrong_version[0] = vec![2, 1, 1];
        let malformed = tlv(
            0x30,
            &[
                ci[0].clone(),
                tlv(0xa0, &tlv(0x30, &wrong_version.concat())),
            ]
            .concat(),
        );
        let invalid = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(malformed), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        );
        assert!(
            !matches!(invalid, Ok(report) if report.verdict == Verdict::Valid),
            "RFC5940 OtherRevocationInfoFormat cannot retain SignedData version 1"
        );
    }
    #[test]
    fn changed_source_status_and_timestamp_signature_are_invalid() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let ci = children(&source);
        let sd = children(&children(&ci[1])[0]);
        let info = children(&children(sd.last().unwrap())[0]);
        let attrs = children(&info[6]);
        let signature_stamp = attrs
            .iter()
            .find(|attr| {
                let fields = children(attr);
                let oid: der::asn1::ObjectIdentifier =
                    der::asn1::ObjectIdentifier::from_der(&fields[0]).unwrap();
                oid.to_string() == "1.2.840.113549.1.9.16.2.14"
            })
            .unwrap();
        let stamp_fields = children(signature_stamp);
        let token = children(&stamp_fields[1])[0].clone();
        let token_ci = children(&token);
        let token_sd = children(&children(&token_ci[1])[0]);
        let tsa_fields = children(&children(token_sd.last().unwrap())[0]);
        let token_signature = AnyRef::from_der(&tsa_fields[5]).unwrap().value().to_vec();
        for target in [DATA.to_vec(), f.crl.clone(), token_signature] {
            let mut altered = source.clone();
            let position = altered
                .windows(target.len())
                .position(|bytes| bytes == target)
                .unwrap();
            altered[position + target.len() - 1] ^= 1;
            let report = ades::verify(
                AdesLevel::B,
                Source::sequential(&mut Cursor::new(altered), None),
                None,
                &services,
                &[SigAlg::RsaSha256],
                &scope(),
            )
            .unwrap();
            assert_eq!(report.verdict, Verdict::Invalid);
            assert_eq!(report.level(), None);
        }
    }
    #[test]
    fn cades_without_signing_time_is_a_profile_finding_and_tampering_is_still_a_failure() {
        use oncl_pki::{
            cms::{self, AttrSpec, CertSpec, CoSign, Content, Problem, SignSpec},
            validation::{CheckStatus, ProfileViolation, ValidationReason},
        };
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let mut attrs = AttrSpec::cades(NOW);
        attrs.signing_time = None;
        let source = cms::sign_spec(
            &f.doc,
            &[],
            &SignSpec {
                content: Content::Data(DATA),
                encapsulate: true,
                cosign: CoSign::Never,
                econtent_type: None,
                digest: None,
                attrs,
                certificates: CertSpec::Signer,
            },
        )
        .unwrap();
        cms::verify(&source, None).unwrap();
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let check = |bytes: Vec<u8>| {
            ades::verify(
                AdesLevel::B,
                Source::sequential(&mut Cursor::new(bytes), None),
                None,
                &services,
                &[SigAlg::RsaSha256],
                &scope(),
            )
            .unwrap()
        };
        // EN 319 122-1 clause 5.2.1 wants a signing-time; its absence is a profile finding on
        // a signature that otherwise verifies, not a malformed or failed signature.
        let report = check(source.clone());
        let signer = &report.reports()[0].signers[0];
        assert_eq!(signer.signature, CheckStatus::Passed);
        assert!(
            signer.reasons.contains(&ValidationReason::Profile(
                ProfileViolation::SigningTimeMissing
            )),
            "{:?}",
            signer.reasons
        );
        assert!(
            signer
                .reasons
                .iter()
                .all(|reason| !matches!(reason, ValidationReason::Signature(_))),
            "{:?}",
            signer.reasons
        );
        assert_eq!(signer.ades_level, None);
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.level(), None);
        // The same content bytes altered: a real signature failure, reported as one.
        let mut altered = source.clone();
        let at = altered.windows(DATA.len()).position(|w| w == DATA).unwrap();
        altered[at] ^= 1;
        let report = check(altered);
        let signer = &report.reports()[0].signers[0];
        assert_eq!(signer.signature, CheckStatus::Failed);
        assert!(
            signer
                .reasons
                .contains(&ValidationReason::Signature(Problem::DigestMismatch))
        );
        assert_eq!(report.verdict, Verdict::Invalid);
    }
    #[test]
    fn other_baseline_violations_are_profile_findings_with_a_passed_signature() {
        use oncl_pki::{
            cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec},
            validation::{CheckStatus, ProfileViolation, ValidationReason},
        };
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let not_data = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
        let mut without_ess = AttrSpec::cades(NOW);
        without_ess.signing_certificate_v2 = false;
        let cases = [
            (
                "content type",
                Some(not_data),
                AttrSpec::cades(NOW),
                ProfileViolation::ContentTypeNotData,
            ),
            (
                "signing certificate",
                None,
                without_ess,
                ProfileViolation::SigningCertificateMissing,
            ),
        ];
        for (name, econtent_type, attrs, expected) in cases {
            let source = cms::sign_spec(
                &f.doc,
                &[],
                &SignSpec {
                    content: Content::Data(DATA),
                    encapsulate: true,
                    cosign: CoSign::Never,
                    econtent_type,
                    digest: None,
                    attrs,
                    certificates: CertSpec::Signer,
                },
            )
            .unwrap();
            let report = ades::verify(
                AdesLevel::B,
                Source::sequential(&mut Cursor::new(source.clone()), None),
                None,
                &services,
                &[SigAlg::RsaSha256],
                &scope(),
            )
            .unwrap();
            let signer = &report.reports()[0].signers[0];
            assert_eq!(signer.signature, CheckStatus::Passed, "{name}");
            let profile_reasons: Vec<_> = signer
                .reasons
                .iter()
                .filter(|r| matches!(r, ValidationReason::Profile(_)))
                .collect();
            assert_eq!(
                profile_reasons,
                vec![&ValidationReason::Profile(expected)],
                "{name}: {:?}",
                signer.reasons
            );
            assert!(
                signer
                    .reasons
                    .iter()
                    .all(|r| !matches!(r, ValidationReason::Signature(_))),
                "{name}: {:?}",
                signer.reasons
            );
            assert_eq!(signer.ades_level, None, "{name}");
            assert_eq!(report.verdict, Verdict::Invalid, "{name}");
        }
    }
    #[test]
    fn missing_acquisition_configuration_precedes_private_application() {
        use oncl_pki::{
            digest::DigestValue,
            key::{DigestSigner, KeyError},
        };
        struct Never {
            key: KeyEntry,
        }
        impl DigestSigner for Never {
            fn certificate(&self) -> &Certificate {
                &self.key.cert
            }
            fn algorithm(&self) -> SigAlg {
                SigAlg::RsaSha256
            }
            fn sign_digest(&mut self, _: &DigestValue) -> Result<Vec<u8>, KeyError> {
                panic!("missing TSA configuration must precede key use")
            }
        }
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let mut output = Vec::new();
        let mut signer = Never { key: f.doc };
        let error = ades::sign(
            &CmsSignRequest::create(true),
            AdesLevel::T,
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, Some(&store)),
            None,
            &mut output,
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(error, ades::AdesError::MissingConfiguration));
        assert!(output.is_empty());
    }
    #[test]
    fn cancellation_and_foreign_staged_output_remain_fatal() {
        struct Cancel;
        impl OperationControl for Cancel {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                Err(ProcessingError::Cancelled)
            }
        }
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let limits = limits();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let cancelled = budget.begin(limits, Arc::new(Cancel)).unwrap();
        let error = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(baseline(&f, true, NOW, &store)), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &cancelled,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ades::AdesError::Processing(ProcessingError::Cancelled)
                | ades::AdesError::Stream(oncl_pki::cms::stream::StreamError::Processing(
                    ProcessingError::Cancelled
                ))
        ));
        let mut owner = scope();
        let other = scope();
        let mut output = store.stage(&mut owner).unwrap();
        let error = ades::extend_staged(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(baseline(&f, true, NOW, &store)), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &mut output,
            &other,
        )
        .unwrap_err();
        assert!(error.to_string().contains("empty live output artifact"));
        assert!(output.is_empty());
    }
    #[test]
    fn archive_graph_uses_protected_predecessors_not_unsigned_set_storage_order() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let (renewed, _) = run(
            &f,
            &source,
            true,
            AdesLevel::Lta,
            NOW + time::Duration::MINUTE,
        );
        let ci = children(&renewed);
        let mut sd = children(&children(&ci[1])[0]);
        let mut signers = children(sd.last().unwrap());
        let mut fields = children(&signers[0]);
        let mut attrs = children(&fields[6]);
        attrs.reverse();
        fields[6] = tlv(0xa1, &attrs.concat());
        signers[0] = tlv(0x30, &fields.concat());
        let last = sd.len() - 1;
        sd[last] = tlv(0x31, &signers.concat());
        let reordered = tlv(
            0x30,
            &[ci[0].clone(), tlv(0xa0, &tlv(0x30, &sd.concat()))].concat(),
        );
        let (_, report) = run(
            &f,
            &reordered,
            true,
            AdesLevel::Lta,
            NOW + time::Duration::minutes(2),
        );
        assert_eq!(report.verdict, Verdict::Valid);
    }
    #[test]
    fn source_replay_and_internal_cms_spools_use_one_input_and_output_allowance() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        // Exact output-size comparison needs deterministic DER nonce lengths,
        // not the random nonce's optional leading INTEGER sign octet.
        let mut profile = profile();
        profile.nonce = oncl_pki::http::NonceSpec::Value(vec![0x63; 8]);
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let mut first = Vec::new();
        ades::sign(
            &CmsSignRequest::create(true),
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut f.doc.clone()],
            &CmsSignServices::new(Some(&context), Some(&store)),
            Some(&services),
            &mut first,
            &scope(),
        )
        .unwrap();
        let limits = ResourceLimits {
            input_bytes: DATA.len() as u64,
            output_bytes: first.len() as u64,
            ..limits()
        };
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scoped = budget.begin(limits, Arc::new(Control)).unwrap();
        let mut output = store.stage(&mut scoped).unwrap();
        let summary = ades::sign_staged(
            &CmsSignRequest::create(true),
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut f.doc.clone()],
            &CmsSignServices::new(Some(&context), Some(&store)),
            Some(&services),
            &mut output,
            &scoped,
        )
        .unwrap();
        assert_eq!(summary.bytes_in, DATA.len() as u64);
        assert_eq!(summary.bytes_out, output.len());
        assert_eq!(scoped.progress().bytes_in, DATA.len() as u64);
        assert_eq!(scoped.progress().bytes_out, output.len());
        let mut bytes = Vec::new();
        output.copy_to(&mut bytes).unwrap();
        assert_eq!(scoped.progress().bytes_out, bytes.len() as u64);
        assert_eq!(oncl_pki::cms::verify(&bytes, None).unwrap().len(), 1);
    }
    #[test]
    fn evidence_reader_limit_is_fatal_not_a_completed_invalid_report() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let mut services = services(&context, &network, &store, &profile, &certs, &crls);
        services.limits.max_items = 1;
        let error = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(source), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ades::AdesError::Evidence(oncl_pki::evidence::EvidenceError::Limit)
        ));
    }
    #[test]
    fn later_unindexed_unrelated_status_does_not_replace_indexed_proof_material() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let ci = children(&source);
        let mut sd = children(&children(&ci[1])[0]);
        let status_index = sd.iter().position(|value| value[0] == 0xa1).unwrap();
        let mut statuses = children(&sd[status_index]);
        let mut unrelated = f.crl.clone();
        let last = unrelated.len() - 1;
        unrelated[last] ^= 1;
        statuses.push(unrelated);
        sd[status_index] = tlv(0xa1, &statuses.concat());
        let added = tlv(
            0x30,
            &[ci[0].clone(), tlv(0xa0, &tlv(0x30, &sd.concat()))].concat(),
        );
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let report = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(added), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(report.level(), Some(AdesLevel::Lta));
    }
    #[test]
    fn rsa_archive_can_add_both_actual_gost_signature_families_without_fallback() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        for (name, algorithm) in [
            ("user-gost2004-sign", SigAlg::Gost2004),
            ("user-gost2015-sign", SigAlg::Gost2015_512),
        ] {
            let mut signer = entry(name);
            let mut spec = TestCertSpec::from_cert(&signer.cert);
            strip(&mut spec);
            signer.cert = issue_cert(&f.root, spec);
            let mut output = Vec::new();
            ades::sign(
                &CmsSignRequest::add(),
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(&source), None),
                None,
                &mut [&mut signer],
                &CmsSignServices::new(Some(&context), Some(&store)),
                Some(&services),
                &mut output,
                &scope(),
            )
            .unwrap();
            let reports = oncl_pki::cms::verify(&output, None).unwrap();
            assert_eq!(reports.len(), 2);
            let report = ades::verify(
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(output), None),
                None,
                &services,
                &[SigAlg::RsaSha256, algorithm],
                &scope(),
            )
            .unwrap();
            assert_eq!(report.verdict, Verdict::Valid);
            assert_eq!(report.level(), Some(AdesLevel::Lta));
        }
    }
    #[test]
    fn post_private_cancellation_preserves_applied_and_poisons_staged_output() {
        use oncl_pki::{
            cms::stream::StreamError,
            digest::DigestValue,
            key::{AppliedState, DigestSigner, KeyError},
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Flag(Arc<AtomicBool>);
        impl OperationControl for Flag {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                if self.0.load(Ordering::SeqCst) {
                    Err(ProcessingError::Cancelled)
                } else {
                    Ok(())
                }
            }
        }
        struct Flip {
            key: KeyEntry,
            flag: Arc<AtomicBool>,
        }
        impl DigestSigner for Flip {
            fn certificate(&self) -> &Certificate {
                &self.key.cert
            }
            fn algorithm(&self) -> SigAlg {
                SigAlg::RsaSha256
            }
            fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
                let signature = DigestSigner::sign_digest(&mut self.key, digest)?;
                self.flag.store(true, Ordering::SeqCst);
                Ok(signature)
            }
        }
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let limits = limits();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Flag(flag.clone()))).unwrap();
        let mut output = store.stage(&mut scope).unwrap();
        let mut signer = Flip {
            key: f.doc,
            flag: flag.clone(),
        };
        let error = ades::sign_staged(
            &CmsSignRequest::create(true),
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(DATA), None),
            None,
            &mut [&mut signer],
            &CmsSignServices::new(None, Some(&store)),
            None,
            &mut output,
            &scope,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ades::AdesError::Stream(StreamError::AfterKeyUse {
                applied: AppliedState::Applied,
                ..
            })
        ));
        flag.store(false, Ordering::SeqCst);
        let mut bytes = Vec::new();
        assert!(output.copy_to(&mut bytes).is_err());
        assert!(bytes.is_empty());
    }
    // Bounded fixture-only TLV slicing, deliberately retaining received BER
    // length octets instead of asking a DER encoder for archive authority.
    fn wire_children(input: &[u8]) -> Vec<Vec<u8>> {
        fn end(input: &[u8], at: usize) -> (usize, usize) {
            let length = input[at + 1];
            if length < 128 {
                return (at + 2, at + 2 + length as usize);
            }
            let count = (length & 127) as usize;
            assert!((1..=8).contains(&count));
            let mut size = 0usize;
            for byte in &input[at + 2..at + 2 + count] {
                size = size
                    .checked_mul(256)
                    .unwrap()
                    .checked_add(*byte as usize)
                    .unwrap();
            }
            (at + 2 + count, at + 2 + count + size)
        }
        let (mut at, limit) = end(input, 0);
        assert_eq!(limit, input.len());
        let mut result = Vec::new();
        while at < limit {
            let (_, next) = end(input, at);
            assert!(next <= limit);
            result.push(input[at..next].to_vec());
            at = next;
        }
        result
    }
    fn nonminimal_content_type(source: &[u8]) -> Vec<u8> {
        let ci = wire_children(source);
        let mut sd = wire_children(&wire_children(&ci[1])[0]);
        let mut encap = wire_children(&sd[2]);
        assert_eq!(encap[0][0], 6);
        assert!(encap[0][1] < 128);
        encap[0].insert(1, 0x81);
        sd[2] = tlv(0x30, &encap.concat());
        tlv(
            0x30,
            &[ci[0].clone(), tlv(0xa0, &tlv(0x30, &sd.concat()))].concat(),
        )
    }
    fn reissue_archive(f: &Fixture, source: &[u8], outer: oncl_pki::key::HashAlg) -> Vec<u8> {
        use oncl_pki::{digest::HashState, tsp};
        let ci = wire_children(source);
        let mut sd = wire_children(&wire_children(&ci[1])[0]);
        let content_type = wire_children(&sd[2])[0].clone();
        let mut infos = wire_children(sd.last().unwrap());
        for info in &mut infos {
            let mut fields = wire_children(info);
            let mut attrs = wire_children(&fields[6]);
            for attr in &mut attrs {
                let af = wire_children(attr);
                let oid: der::asn1::ObjectIdentifier =
                    der::asn1::ObjectIdentifier::from_der(&af[0]).unwrap();
                if oid.to_string() != "0.4.0.1733.2.4" {
                    continue;
                }
                let old_token = wire_children(&af[1])[0].clone();
                let tc = wire_children(&old_token);
                let td = wire_children(&wire_children(&tc[1])[0]);
                let ts = wire_children(&wire_children(td.last().unwrap())[0]);
                let index_attr = wire_children(&ts[6])[0].clone();
                let index = wire_children(&wire_children(&index_attr)[1])[0].clone();
                let mut document = HashState::new(oncl_pki::key::HashAlg::Sha256);
                document.update(DATA);
                let mut imprint = HashState::new(outer);
                imprint.update(&content_type);
                imprint.update(document.finish().as_bytes());
                for field in &fields[..6] {
                    imprint.update(field);
                }
                imprint.update(&index);
                let digest = imprint.finish();
                let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
                let mut spec = profile();
                spec.hash = outer;
                let token = tsp::request(&spec, digest.as_bytes(), &http).unwrap().token;
                let checked = tsp::verify_token(&token).unwrap();
                assert_eq!(checked.imprint_alg, outer.oid());
                assert_eq!(checked.imprint, digest.as_bytes());
                let nc = wire_children(&token);
                let mut nd = wire_children(&wire_children(&nc[1])[0]);
                let mut ns = wire_children(&wire_children(nd.last().unwrap())[0]);
                assert_eq!(ns.len(), 6);
                ns.push(tlv(0xa1, &index_attr));
                let last = nd.len() - 1;
                nd[last] = tlv(0x31, &tlv(0x30, &ns.concat()));
                let token = tlv(
                    0x30,
                    &[nc[0].clone(), tlv(0xa0, &tlv(0x30, &nd.concat()))].concat(),
                );
                *attr = tlv(0x30, &[af[0].clone(), tlv(0x31, &token)].concat());
            }
            fields[6] = tlv(0xa1, &attrs.concat());
            *info = tlv(0x30, &fields.concat());
        }
        let last = sd.len() - 1;
        sd[last] = tlv(0x31, &infos.concat());
        tlv(
            0x30,
            &[ci[0].clone(), tlv(0xa0, &tlv(0x30, &sd.concat()))].concat(),
        )
    }
    #[test]
    fn received_archive_binds_actual_imprint_algorithm_to_hash_index() {
        use oncl_pki::{
            digest::DigestValue,
            key::{DigestSigner, HashAlg, KeyError},
        };
        struct Spy {
            key: KeyEntry,
            calls: usize,
        }
        impl DigestSigner for Spy {
            fn certificate(&self) -> &Certificate {
                &self.key.cert
            }
            fn algorithm(&self) -> SigAlg {
                SigAlg::RsaSha256
            }
            fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
                self.calls += 1;
                DigestSigner::sign_digest(&mut self.key, digest)
            }
        }
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, positive) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        assert_eq!(positive.level(), Some(AdesLevel::Lta));
        let mixed = reissue_archive(&f, &source, HashAlg::Sha512);
        assert_eq!(oncl_pki::cms::verify(&mixed, None).unwrap().len(), 1);
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let report = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(&mixed), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.level(), None);
        let mut key = f.doc.clone();
        let mut spec = TestCertSpec::from_cert(&key.cert);
        spec.serial = vec![0x63, 0x03, 0x71];
        key.cert = issue_cert(&f.root, spec);
        let mut spy = Spy { key, calls: 0 };
        let mut output = Vec::new();
        let error = ades::sign(
            &CmsSignRequest::add(),
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(mixed), None),
            None,
            &mut [&mut spy],
            &CmsSignServices::new(Some(&context), Some(&store)),
            Some(&services),
            &mut output,
            &scope(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("proofs must validate before Add")
        );
        assert_eq!(spy.calls, 0);
        assert!(output.is_empty());
    }
    #[test]
    fn received_archive_protects_raw_ber_content_type_and_preserves_it_on_extension() {
        use oncl_pki::key::HashAlg;
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let (source, _) = run(
            &f,
            &baseline(&f, true, NOW, &store),
            true,
            AdesLevel::Lta,
            NOW,
        );
        let changed = nonminimal_content_type(&source);
        assert_eq!(oncl_pki::cms::verify(&changed, None).unwrap().len(), 1);
        let http = MockTsa::new(f.tsa.clone()).with_gen_time(NOW);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &f.anchors,
            intermediates: &[],
            http: &http,
        };
        let network = NetworkPolicy::only_endpoints([URL]).unwrap();
        let profile = profile();
        let certs = [f.root.cert.clone(), f.tsa.cert.clone()];
        let crls = [f.crl.as_slice()];
        let services = services(&context, &network, &store, &profile, &certs, &crls);
        let report = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(&changed), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Invalid);
        assert_eq!(report.level(), None);
        let genuine_ber = reissue_archive(&f, &changed, HashAlg::Sha256);
        let report = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&genuine_ber), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        let (extended, report) = run(&f, &genuine_ber, true, AdesLevel::Lta, NOW);
        assert_eq!(report.verdict, Verdict::Valid);
        let ci = wire_children(&extended);
        let sd = wire_children(&wire_children(&ci[1])[0]);
        assert_eq!(&wire_children(&sd[2])[0][..3], &[6, 0x81, 9]);
        let mut key = f.doc.clone();
        let mut spec = TestCertSpec::from_cert(&key.cert);
        spec.serial = vec![0x63, 0x03, 0x72];
        key.cert = issue_cert(&f.root, spec);
        let mut added = Vec::new();
        ades::sign(
            &CmsSignRequest::add(),
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&genuine_ber), None),
            None,
            &mut [&mut key],
            &CmsSignServices::new(Some(&context), Some(&store)),
            Some(&services),
            &mut added,
            &scope(),
        )
        .unwrap();
        let report = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&added), None),
            None,
            &services,
            &[SigAlg::RsaSha256],
            &scope(),
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(report.reports().len(), 2);
        let ci = wire_children(&added);
        let sd = wire_children(&wire_children(&ci[1])[0]);
        assert_eq!(&wire_children(&sd[2])[0][..3], &[6, 0x81, 9]);
    }
}
