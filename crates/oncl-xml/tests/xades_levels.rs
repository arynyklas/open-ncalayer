//! A recognized malformed archive proof must never become lower-level Valid.
use oncl_pki::{
    io::{Source, TemporaryStore},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy},
};
use oncl_testkit::{read, synthetic};
use oncl_xml::{XmlSignProfile, XmlVerifyProfile, sign_source, verify_source};
use std::{io::Cursor, sync::Arc};
struct Control;
struct Offline;
impl oncl_pki::http::HttpTransport for Offline {
    fn send(
        &self,
        _: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        panic!("offline must not fetch")
    }
}
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
#[test]
fn archive_evidence_tamper() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let f = synthetic("user-rsa-sign");
    let mut signer = oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0);
    let mut out = Vec::new();
    sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>signed</data><s Id='s'/></r>"),
            None,
        ),
        &XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            ..Default::default()
        },
        &mut signer,
        &store,
        &mut out,
        &mut scope,
    )
    .unwrap();
    let text=String::from_utf8(out).unwrap().replace("</ds:Signature>","<ds:Object><xades:QualifyingProperties xmlns:xades='http://uri.etsi.org/01903/v1.3.2#' Target='#unbound'><xades:UnsignedProperties><xades:UnsignedSignatureProperties><a:ArchiveTimeStamp xmlns:a='http://uri.etsi.org/01903/v1.4.1#'><xades:EncapsulatedTimeStamp>AA==</xades:EncapsulatedTimeStamp></a:ArchiveTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature>");
    let http = Offline;
    let anchors = oncl_pki::pkix::CaSet::new(vec![]);
    let ctx = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::now_utc(),
        anchors: &anchors,
        intermediates: &[],
        http: &http,
    };
    assert!(
        verify_source(
            Source::sequential(&mut Cursor::new(text), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut scope
        )
        .is_err()
    );
}

#[test]
fn source_baseline_b_binds_signing_certificate_and_properties_reference() {
    use oncl_pki::evidence::AdesLevel;
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let f = synthetic("user-rsa-sign");
    let mut key = oncl_pki::pkcs12::load(&read(&f.path), &f.password)
        .unwrap()
        .remove(0);
    let anchors = oncl_pki::pkix::CaSet::new(vec![
        oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
    ]);
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now,
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let network = NetworkPolicy::deny_all();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: None,
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig-b"),
            ..Default::default()
        },
        level: AdesLevel::B,
        signing_time: now,
    };
    let mut bytes = Vec::new();
    oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut key,
        &services,
        &mut bytes,
        &mut scope,
    )
    .unwrap();
    let report = verify_source(
        Source::sequential(&mut Cursor::new(&bytes), None),
        &XmlVerifyProfile::default(),
        &store,
        &context,
        &network,
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.signatures()[0].level, Some(AdesLevel::B));
    assert_eq!(report.signatures()[0].references().len(), 2);
    assert!(
        report.signatures()[0]
            .references()
            .iter()
            .all(|r| r.digest_matches)
    );
    drop(report);
    let tampered = String::from_utf8(bytes)
        .unwrap()
        .replace("2026-11-02T12:00:00Z", "2026-11-01T12:00:00Z");
    let report = verify_source(
        Source::sequential(&mut Cursor::new(tampered), None),
        &XmlVerifyProfile::default(),
        &store,
        &context,
        &network,
        &mut scope,
    )
    .unwrap();
    assert_eq!(
        report.validation.signers[0].signature,
        oncl_pki::validation::CheckStatus::Failed
    );
}

type Clock = Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>;
/// A responder that stamps its answer with the host clock at the instant of the request.
struct Live {
    key: oncl_pki::pkcs12::KeyEntry,
    tsa: bool,
    clock: Clock,
}
impl oncl_pki::http::HttpTransport for Live {
    fn send(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        let now = (self.clock)();
        if self.tsa {
            oncl_pki::tsp::MockTsa::new(self.key.clone())
                .with_gen_time(now)
                .send(request)
        } else {
            oncl_pki::ocsp::MockOcsp::new(self.key.clone())
                .with_now(now)
                .send(request)
        }
    }
}
/// Operation time that advances only while the operation does work: every checkpoint (taken per
/// parsed event of every document pass and per evidence step) costs `step`.
struct Ticking {
    now: std::sync::Mutex<time::OffsetDateTime>,
    step: time::Duration,
}
impl Ticking {
    fn new(start: time::OffsetDateTime, step: time::Duration) -> Arc<Self> {
        Arc::new(Self {
            now: std::sync::Mutex::new(start),
            step,
        })
    }
    fn read(&self) -> time::OffsetDateTime {
        *self.now.lock().unwrap()
    }
}
impl OperationControl for Ticking {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        *self.now.lock().unwrap() += self.step;
        Ok(())
    }
}
struct Pki {
    signer: oncl_pki::pkcs12::KeyEntry,
    anchors: oncl_pki::pkix::CaSet,
    http: oncl_pki::http::RouteTransport,
    tsa: oncl_pki::tsp::TsaSpec,
    /// Kept to re-route the fixed-clock mock responders (`with_ocsp`).
    responder: oncl_pki::pkcs12::KeyEntry,
    tsa_key: oncl_pki::pkcs12::KeyEntry,
    tsa_now: time::OffsetDateTime,
}
impl Pki {
    /// The same world with the OCSP route answered by `make(responder, tsa key)`.
    fn with_ocsp(
        mut self,
        make: impl FnOnce(
            oncl_pki::pkcs12::KeyEntry,
            oncl_pki::pkcs12::KeyEntry,
        ) -> oncl_pki::ocsp::MockOcsp,
    ) -> Self {
        let ocsp = make(self.responder.clone(), self.tsa_key.clone());
        self.http = oncl_pki::http::RouteTransport::new(vec![
            (
                self.tsa.url.clone(),
                Arc::new(
                    oncl_pki::tsp::MockTsa::new(self.tsa_key.clone()).with_gen_time(self.tsa_now),
                ) as Arc<dyn oncl_pki::http::HttpTransport>,
            ),
            (
                "http://ocsp.synthetic.test".into(),
                Arc::new(ocsp) as Arc<dyn oncl_pki::http::HttpTransport>,
            ),
        ]);
        self
    }
    fn new(name: &str) -> Self {
        Self::at(name, time::macros::datetime!(2026-11-02 12:00 UTC))
    }
    /// TSA genTime and OCSP thisUpdate as minted by responders at `now`.
    fn at(name: &str, now: time::OffsetDateTime) -> Self {
        Self::at_split(name, now, now, None)
    }
    /// Responders that answer as of the host clock at the instant of each request.
    fn live(name: &str, clock: Clock) -> Self {
        let now = clock();
        Self::at_split(name, now, now, Some(clock))
    }
    /// A TSA whose reply genTime is `tsa_now` while OCSP is minted at `now`.
    fn at_split(
        name: &str,
        now: time::OffsetDateTime,
        tsa_now: time::OffsetDateTime,
        live: Option<Clock>,
    ) -> Self {
        use oncl_pki::{
            http::RouteTransport,
            ocsp::MockOcsp,
            testing::{TestCertSpec, issue_cert},
            tsp::{MockTsa, TsaProfile, TsaSpec},
        };
        fn key(name: &str) -> oncl_pki::pkcs12::KeyEntry {
            let f = synthetic(name);
            oncl_pki::pkcs12::load(&read(&f.path), &f.password)
                .unwrap()
                .remove(0)
        }
        let root = key("root-gost2015.key");
        let aia = TestCertSpec::from_cert(&key("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            })
            .collect::<Vec<_>>();
        let mut signer = key(name);
        let mut spec = TestCertSpec::from_cert(&signer.cert);
        spec.extensions.retain(|e| {
            !matches!(
                e.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        });
        spec.extensions.extend(aia.clone());
        signer.cert = issue_cert(&root, spec);
        let mut tsa_key = key("tsa-gost2015");
        let mut spec = TestCertSpec::from_cert(&tsa_key.cert);
        spec.extensions.retain(|e| {
            !matches!(
                e.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        });
        spec.extensions.extend(aia);
        tsa_key.cert = issue_cert(&root, spec);
        let mut responder = key("ocsp-gost2015");
        responder.cert = issue_cert(&root, TestCertSpec::from_cert(&responder.cert));
        let (responder_key, tsa_key_kept) = (responder.clone(), tsa_key.clone());
        let mut tsa = TsaSpec::from(TsaProfile::basics_default());
        tsa.url = "http://tsa.synthetic.test".into();
        let (tsa_route, ocsp_route): (
            Arc<dyn oncl_pki::http::HttpTransport>,
            Arc<dyn oncl_pki::http::HttpTransport>,
        ) = if let Some(clock) = live {
            (
                Arc::new(Live {
                    key: tsa_key,
                    tsa: true,
                    clock: clock.clone(),
                }),
                Arc::new(Live {
                    key: responder,
                    tsa: false,
                    clock,
                }),
            )
        } else {
            (
                Arc::new(MockTsa::new(tsa_key).with_gen_time(tsa_now)),
                Arc::new(MockOcsp::new(responder).with_now(now)),
            )
        };
        let http = RouteTransport::new(vec![
            (tsa.url.clone(), tsa_route),
            ("http://ocsp.synthetic.test".into(), ocsp_route),
        ]);
        Self {
            signer,
            anchors: oncl_pki::pkix::CaSet::new(vec![root.cert]),
            http,
            tsa,
            responder: responder_key,
            tsa_key: tsa_key_kept,
            tsa_now,
        }
    }
}
#[test]
fn all_baseline_levels_check_crypto_evidence_and_document_not_presence() {
    use oncl_pki::{
        evidence::AdesLevel,
        validation::{CheckStatus, Verdict},
    };
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let mut pki = Pki::new(name);
        for level in [AdesLevel::B, AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta] {
            let limits = ResourceLimits::default();
            let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
            let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
            let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
            let now = time::macros::datetime!(2026-11-02 12:00 UTC);
            let context = ValidationContext {
                policy: ValidationPolicy::StrictOnline,
                now,
                anchors: &pki.anchors,
                intermediates: &[],
                http: &pki.http,
            };
            let network = NetworkPolicy::only_endpoints([
                "http://tsa.synthetic.test",
                "http://ocsp.synthetic.test",
            ])
            .unwrap();
            let services = XadesServices {
                validation: &context,
                network: &network,
                temporary: &store,
                tsa: Some(&pki.tsa),
                material: oncl_pki::cms::ades::ValidationMaterial {
                    certificates: &[],
                    ocsp: &[],
                    crls: &[],
                },
                evidence_limits: None,
                host_clock: None,
            };
            let spec = XadesSourceSpec {
                xml: XmlSignProfile {
                    target: Some("p"),
                    parent: Some("s"),
                    signature_id: Some("sig"),
                    ..Default::default()
                },
                level,
                signing_time: now,
            };
            let mut bytes = Vec::new();
            let result = oncl_xml::xades::sign_source(
                Source::sequential(
                    &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
                    None,
                ),
                &spec,
                &mut pki.signer,
                &services,
                &mut bytes,
                &mut scope,
            )
            .unwrap_or_else(|e| panic!("{name}/{level:?}: {e:?}"));
            assert_eq!(
                result.verification.validation.verdict,
                Verdict::Valid,
                "{name}/{level:?}: {result:?}"
            );
            assert_eq!(result.verification.signatures()[0].level, Some(level));
            assert!(
                result.verification.signatures()[0]
                    .references()
                    .iter()
                    .all(|r| r.digest_matches)
            );
            if level > AdesLevel::B {
                assert!(
                    result.verification.validation.signers[0]
                        .proof_time
                        .is_some()
                );
            }
            drop(result);
            let mutation = String::from_utf8(bytes.clone())
                .unwrap()
                .replace(">protected<", ">FORGED<");
            let report = verify_source(
                Source::sequential(&mut Cursor::new(mutation), None),
                &XmlVerifyProfile::default(),
                &store,
                &context,
                &network,
                &mut scope,
            )
            .unwrap();
            assert_eq!(report.validation.signers[0].signature, CheckStatus::Failed);
            drop(report);
            if level == AdesLevel::Lta {
                let mut mutation = String::from_utf8(bytes).unwrap();
                let start = mutation.find("<xades:EncapsulatedOCSPValue>").unwrap()
                    + "<xades:EncapsulatedOCSPValue>".len();
                let byte = if &mutation[start..start + 1] == "A" {
                    "B"
                } else {
                    "A"
                };
                mutation.replace_range(start..start + 1, byte);
                let report = verify_source(
                    Source::sequential(&mut Cursor::new(mutation), None),
                    &XmlVerifyProfile::default(),
                    &store,
                    &context,
                    &network,
                    &mut scope,
                )
                .unwrap();
                assert_ne!(report.validation.verdict, Verdict::Valid);
                assert_eq!(report.validation.signers[0].timestamp, CheckStatus::Failed);
            }
        }
    }
}

#[test]
fn proof_only_extension_and_renewal_preserve_all_old_proofs() {
    use oncl_pki::evidence::AdesLevel;
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let mut pki = Pki::new("user-rsa-sign");
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let new_scope = || {
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        budget.begin(limits, Arc::new(Control)).unwrap()
    };
    let mut bytes = Vec::new();
    let mut scope = new_scope();
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: AdesLevel::B,
        signing_time: now,
    };
    let report = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .unwrap();
    drop(report);
    drop(scope);
    let original = String::from_utf8(bytes.clone()).unwrap();
    let original_doc = roxmltree::Document::parse(&original).unwrap();
    let signature = original_doc
        .descendants()
        .find(|n| n.tag_name().name() == "SignatureValue")
        .unwrap()
        .text()
        .unwrap();
    let mut old_tokens = Vec::<String>::new();
    for level in [AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta, AdesLevel::Lta] {
        let mut scope = new_scope();
        let mut out = Vec::new();
        let result = oncl_xml::xades::extend_source(
            Source::sequential(&mut Cursor::new(&bytes), None),
            level,
            &XmlVerifyProfile::default(),
            &services,
            &mut out,
            &mut scope,
        )
        .unwrap();
        assert_eq!(result.verification.signatures()[0].level, Some(level));
        assert_eq!(
            result.verification.validation.verdict,
            oncl_pki::validation::Verdict::Valid
        );
        let text = std::str::from_utf8(&out).unwrap();
        let parsed = roxmltree::Document::parse(text).unwrap();
        assert_eq!(
            parsed
                .descendants()
                .find(|n| n.tag_name().name() == "SignatureValue")
                .unwrap()
                .text()
                .unwrap(),
            signature
        );
        let tokens = parsed
            .descendants()
            .filter(|n| n.tag_name().name() == "EncapsulatedTimeStamp")
            .map(|n| n.text().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(&tokens[..old_tokens.len()], old_tokens.as_slice());
        old_tokens = tokens;
        bytes = out;
    }
    assert_eq!(
        old_tokens.len(),
        3,
        "signature-time proof plus two archives"
    );
    let mut bad = String::from_utf8(bytes).unwrap();
    let start =
        bad.find("<xades:EncapsulatedTimeStamp>").unwrap() + "<xades:EncapsulatedTimeStamp>".len();
    bad.replace_range(start..start + 1, "!");
    let mut out = Vec::new();
    let mut scope = new_scope();
    assert!(
        oncl_xml::xades::extend_source(
            Source::sequential(&mut Cursor::new(bad), None),
            AdesLevel::Lta,
            &XmlVerifyProfile::default(),
            &services,
            &mut out,
            &mut scope
        )
        .is_err()
    );
    assert!(out.is_empty());
}

#[test]
fn rotated_current_tsa_data_is_noncyclic_and_next_archive_protects_it() {
    use oncl_pki::{
        evidence::AdesLevel,
        http::{HttpError, HttpReply, HttpRequest, HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        testing::{TestCertSpec, issue_cert},
        tsp::MockTsa,
        validation::Verdict,
    };
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Rotate {
        old: MockTsa,
        current: MockTsa,
        calls: AtomicUsize,
    }
    impl HttpTransport for Rotate {
        fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.old.send(request)
            } else {
                self.current.send(request)
            }
        }
    }
    let load = |name: &str| {
        let f = synthetic(name);
        oncl_pki::pkcs12::load(&read(&f.path), &f.password)
            .unwrap()
            .remove(0)
    };
    let mut pki = Pki::new("user-rsa-sign");
    let root = load("root-gost2015.key");
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let mut old = load("tsa-gost2015");
    let mut spec = TestCertSpec::from_cert(&old.cert);
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions.extend(
        TestCertSpec::from_cert(&pki.signer.cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    spec.serial = vec![0x74, 0x20];
    old.cert = issue_cert(&root, spec);
    let mut current = old.clone();
    let mut spec = TestCertSpec::from_cert(&current.cert);
    spec.serial = vec![0x74, 0x21];
    current.cert = issue_cert(&root, spec);
    let mut responder = load("ocsp-gost2015");
    responder.cert = issue_cert(&root, TestCertSpec::from_cert(&responder.cert));
    let rotate = Arc::new(Rotate {
        old: MockTsa::new(old).with_gen_time(now),
        current: MockTsa::new(current).with_gen_time(now),
        calls: AtomicUsize::new(0),
    });
    let http = RouteTransport::new(vec![
        (
            pki.tsa.url.clone(),
            rotate.clone() as Arc<dyn HttpTransport>,
        ),
        (
            "http://ocsp.synthetic.test".into(),
            Arc::new(MockOcsp::new(responder).with_now(now)),
        ),
    ]);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let new_scope = || {
        let cap = ResourceLimits::default();
        Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap()
    };
    let mut scope = new_scope();
    let mut bytes = Vec::new();
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: AdesLevel::Lta,
        signing_time: now,
    };
    let report = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><p Id='p'>covered</p><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.verification.validation.verdict, Verdict::Valid);
    drop(report);
    drop(scope);
    assert_eq!(rotate.calls.load(Ordering::SeqCst), 2);
    let text = String::from_utf8(bytes.clone()).unwrap();
    let parsed = roxmltree::Document::parse(&text).unwrap();
    let archive = parsed
        .descendants()
        .find(|n| n.tag_name().name() == "ArchiveTimeStamp")
        .unwrap();
    let tail = archive.next_sibling_element().unwrap();
    assert_eq!(tail.tag_name().name(), "TimeStampValidationData");
    assert_eq!(
        tail.attribute("URI").unwrap(),
        format!("#{}", archive.attribute("Id").unwrap())
    );
    let bad_uri = text.replacen(
        &format!("URI=\"#{}\"", archive.attribute("Id").unwrap()),
        "URI=\"#unrelated\"",
        1,
    );
    let mut scope = new_scope();
    assert!(
        verify_source(
            Source::sequential(&mut Cursor::new(bad_uri), None),
            &XmlVerifyProfile::default(),
            &store,
            &context,
            &network,
            &mut scope
        )
        .is_err()
    );
    let unknown = text.replace(
        "</xades:UnsignedSignatureProperties>",
        "<unknown xmlns='urn:unknown'/></xades:UnsignedSignatureProperties>",
    );
    let mut scope = new_scope();
    assert!(
        verify_source(
            Source::sequential(&mut Cursor::new(unknown), None),
            &XmlVerifyProfile::default(),
            &store,
            &context,
            &network,
            &mut scope
        )
        .is_err()
    );
    let mut scope = new_scope();
    let mut renewed = Vec::new();
    let report = oncl_xml::xades::extend_source(
        Source::sequential(&mut Cursor::new(&bytes), None),
        AdesLevel::Lta,
        &XmlVerifyProfile::default(),
        &services,
        &mut renewed,
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.verification.validation.verdict, Verdict::Valid);
    drop(report);
    let mut mutation = String::from_utf8(renewed).unwrap();
    let at = mutation.find("URI=\"#sig-A1\"").unwrap();
    mutation.replace_range(at..at + "URI=\"#sig-A1\"".len(), "URI=\"#forged\"");
    let mut scope = new_scope();
    let result = verify_source(
        Source::sequential(&mut Cursor::new(mutation), None),
        &XmlVerifyProfile::default(),
        &store,
        &context,
        &network,
        &mut scope,
    );
    assert!(result.is_err() || result.unwrap().validation.verdict != Verdict::Valid);
}

#[test]
fn host_evidence_limits_preflight_lta_and_restrict_carried_proofs() {
    use oncl_pki::{
        evidence::{AdesLevel, EvidenceError, EvidenceLimits},
        key::{DigestSigner, SigAlg},
    };
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let mut pki = Pki::new("user-rsa-sign");
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let cap = EvidenceLimits {
        max_items: 1,
        max_bytes: 6291456,
        max_item_bytes: 262144,
        max_crl_bytes: 6291456,
        max_crl_item_bytes: 262144,
        max_total_bytes: 6291456,
        max_chain_len: 16,
        max_proofs: 1,
        max_coverage_parts: 256,
        max_coverage_bytes: 1 << 40,
    };
    let mut services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: Some(cap),
        host_clock: None,
    };
    struct Count<'a> {
        key: &'a mut oncl_pki::pkcs12::KeyEntry,
        calls: usize,
    }
    impl DigestSigner for Count<'_> {
        fn certificate(&self) -> &oncl_pki::cert::Certificate {
            self.key.certificate()
        }
        fn algorithm(&self) -> SigAlg {
            self.key.algorithm()
        }
        fn sign_digest(
            &mut self,
            d: &oncl_pki::digest::DigestValue,
        ) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
            self.calls += 1;
            self.key.sign_digest(d)
        }
    }
    let mut signer = Count {
        key: &mut pki.signer,
        calls: 0,
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: AdesLevel::Lta,
        signing_time: now,
    };
    let new_scope = || {
        let cap = ResourceLimits::default();
        Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap()
    };
    let mut scope = new_scope();
    let mut out = Vec::new();
    let error = oncl_xml::xades::sign_source(
        Source::sequential(&mut Cursor::new(b"<r/>"), None),
        &spec,
        &mut signer,
        &services,
        &mut out,
        &mut scope,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        oncl_xml::XmlSourceError::Evidence(EvidenceError::Limit)
    ));
    assert_eq!(signer.calls, 0);
    assert!(out.is_empty());
    drop(scope);
    services.evidence_limits = None;
    let mut scope = new_scope();
    let report = oncl_xml::xades::sign_source(
        Source::sequential(&mut Cursor::new(b"<r/>"), None),
        &spec,
        &mut signer,
        &services,
        &mut out,
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.verification.minimum_level(), Some(AdesLevel::Lta));
    drop(report);
    drop(scope);
    let mut scope = new_scope();
    let profile = XmlVerifyProfile {
        evidence_limits: Some(EvidenceLimits {
            max_items: 24,
            ..cap
        }),
        ..Default::default()
    };
    assert!(matches!(
        verify_source(
            Source::sequential(&mut Cursor::new(out), None),
            &profile,
            &store,
            &context,
            &network,
            &mut scope
        ),
        Err(oncl_xml::XmlSourceError::Evidence(EvidenceError::Limit))
    ));
}

#[test]
fn recognized_archive_and_tsvd_require_exact_signature_location() {
    use oncl_pki::evidence::AdesLevel;
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let mut pki = Pki::new("user-rsa-sign");
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: None,
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let new_scope = || {
        let cap = ResourceLimits::default();
        Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap()
    };
    let mut scope = new_scope();
    let mut bytes = Vec::new();
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: AdesLevel::B,
        signing_time: now,
    };
    let report = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><p Id='p'>protected</p><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .unwrap();
    drop(report);
    drop(scope);
    let text = String::from_utf8(bytes).unwrap();
    let archive = "<a:ArchiveTimeStamp xmlns:a='http://uri.etsi.org/01903/v1.4.1#'/>";
    let tsvd = "<a:TimeStampValidationData xmlns:a='http://uri.etsi.org/01903/v1.4.1#'/>";
    for (name, mutation) in [
        (
            "sibling archive",
            text.replace("</r>", &format!("{archive}</r>")),
        ),
        ("sibling TSVD", text.replace("</r>", &format!("{tsvd}</r>"))),
        (
            "Signature TSVD",
            text.replacen("<ds:Object>", &format!("{tsvd}<ds:Object>"), 1),
        ),
        (
            "Object TSVD",
            text.replacen("<ds:Object>", &format!("<ds:Object>{tsvd}"), 1),
        ),
        (
            "Object archive",
            text.replacen("<ds:Object>", &format!("<ds:Object>{archive}"), 1),
        ),
    ] {
        assert!(
            oncl_xml::verify(mutation.as_bytes()).is_ok(),
            "stable signed targets must remain cryptographically unchanged: {name}"
        );
        let mut scope = new_scope();
        assert!(
            verify_source(
                Source::sequential(&mut Cursor::new(mutation), None),
                &XmlVerifyProfile::default(),
                &store,
                &context,
                &network,
                &mut scope
            )
            .is_err(),
            "recognized material was silently ignored: {name}"
        );
    }
}

#[test]
fn genuine_independent_signature_time_proofs_are_explicitly_unsupported() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use oncl_pki::{digest::HashState, evidence::AdesLevel};
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let mut pki = Pki::new("user-rsa-sign");
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let new_scope = || {
        let cap = ResourceLimits::default();
        Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap()
    };
    let mut scope = new_scope();
    let mut bytes = Vec::new();
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: AdesLevel::T,
        signing_time: now,
    };
    let report = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><p Id='p'>protected</p><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .unwrap();
    drop(report);
    drop(scope);
    let mut scope = new_scope();
    let mut document = oncl_xml::XmlDocument::index(
        Source::sequential(&mut Cursor::new(&bytes), None),
        &oncl_xml::XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    let value = document
        .select_xpath(
            "//ds:SignatureValue",
            &[("ds", "http://www.w3.org/2000/09/xmldsig#")],
            &mut scope,
        )
        .unwrap()
        .unwrap();
    let mut canonical = Vec::new();
    document
        .canonicalize(
            Some(&value),
            oncl_xml::C14n::Exclusive,
            oncl_xml::C14nProfile::Standard,
            &mut canonical,
            &mut scope,
        )
        .unwrap();
    drop(document);
    drop(scope);
    let mut hash = HashState::new(pki.tsa.hash);
    hash.update(&canonical);
    let imprint = hash.finish();
    let text = String::from_utf8(bytes).unwrap();
    let parsed = roxmltree::Document::parse(&text).unwrap();
    let first = STANDARD
        .decode(
            parsed
                .descendants()
                .find(|n| n.tag_name().name() == "EncapsulatedTimeStamp")
                .unwrap()
                .text()
                .unwrap(),
        )
        .unwrap();
    oncl_pki::tsp::verify_token_imprint(&first, &imprint).unwrap();
    let second = oncl_pki::tsp::request(&pki.tsa, imprint.as_bytes(), &pki.http)
        .unwrap()
        .token;
    oncl_pki::tsp::verify_token_imprint(&second, &imprint).unwrap();
    assert_ne!(
        first, second,
        "independent genuine requests must not be a duplicated token"
    );
    let extra = format!(
        "<xades:SignatureTimeStamp Id='independent-T-2'><ds:CanonicalizationMethod Algorithm='{}'/><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>",
        oncl_xml::C14n::Exclusive.uri(),
        STANDARD.encode(second)
    );
    let mutation = text.replace(
        "</xades:UnsignedSignatureProperties>",
        &format!("{extra}</xades:UnsignedSignatureProperties>"),
    );
    let mut scope = new_scope();
    assert!(matches!(
        verify_source(
            Source::sequential(&mut Cursor::new(mutation), None),
            &XmlVerifyProfile::default(),
            &store,
            &context,
            &network,
            &mut scope
        ),
        Err(oncl_xml::XmlSourceError::Unsupported(
            "multiple independent SignatureTimeStamp proofs"
        ))
    ));
}

#[test]
fn baseline_data_object_format_binds_reference_and_legacy_has_no_false_level() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    use oncl_xml::xades::{XadesLevel, XadesServices, XadesSourceSpec, XadesSpec};
    let mut pki = Pki::new("user-rsa-sign");
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: None,
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let new_scope = || {
        let cap = ResourceLimits::default();
        Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap()
    };
    let mut scope = new_scope();
    let mut bytes = Vec::new();
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: AdesLevel::B,
        signing_time: now,
    };
    let report = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><p Id='p'>protected</p><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.verification.minimum_level(), Some(AdesLevel::B));
    drop(report);
    drop(scope);
    let text = std::str::from_utf8(&bytes).unwrap();
    let parsed = roxmltree::Document::parse(text).unwrap();
    let reference = parsed
        .descendants()
        .find(|n| {
            n.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
                && n.tag_name().name() == "Reference"
                && n.attribute("URI") == Some("#p")
        })
        .unwrap();
    let id = reference
        .attribute("Id")
        .expect("baseline data Reference needs identity");
    let format = parsed
        .descendants()
        .find(|n| {
            n.tag_name().namespace() == Some("http://uri.etsi.org/01903/v1.3.2#")
                && n.tag_name().name() == "DataObjectFormat"
        })
        .expect("EN319132-1 6.3k mandatory DataObjectFormat");
    assert_eq!(
        format.attribute("ObjectReference").unwrap(),
        format!("#{id}")
    );
    assert_eq!(
        format
            .children()
            .find(|n| n.tag_name().name() == "MimeType")
            .unwrap()
            .text(),
        Some("application/xml")
    );
    let legacy = oncl_xml::xades::sign(
        b"<r>legacy protected</r>",
        &XadesSpec {
            level: XadesLevel::B,
            tsa: None,
            chain: vec![],
            signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            digest_method: None,
        },
        &pki.signer.key,
        &pki.signer.cert,
        &pki.http,
        now,
    )
    .unwrap();
    let mut scope = new_scope();
    let report = verify_source(
        Source::sequential(&mut Cursor::new(&legacy), None),
        &XmlVerifyProfile::default(),
        &store,
        &context,
        &network,
        &mut scope,
    )
    .unwrap();
    assert_eq!(report.validation.verdict, Verdict::Valid);
    assert_eq!(
        report.minimum_level(),
        None,
        "legacy crypto shape without DataObjectFormat is not complete new baseline"
    );
    drop(report);
    drop(scope);
    let mut scope = new_scope();
    assert!(
        verify_source(
            Source::sequential(&mut Cursor::new(legacy), None),
            &XmlVerifyProfile {
                required_level: Some(AdesLevel::B),
                ..Default::default()
            },
            &store,
            &context,
            &network,
            &mut scope
        )
        .is_err()
    );
}

#[test]
fn guarded_bounded_xades_spec_uses_shared_real_evidence_for_b_t_lt() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    use oncl_xml::xades::{XadesLevel, XadesServices, XadesSpec};
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let mut pki = Pki::new(name);
        for (level, expected) in [
            (XadesLevel::B, AdesLevel::B),
            (XadesLevel::T, AdesLevel::T),
            (XadesLevel::Lt, AdesLevel::Lt),
        ] {
            let limits = ResourceLimits::default();
            let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
            let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
            let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
            let now = time::macros::datetime!(2026-11-02 12:00 UTC);
            let context = ValidationContext {
                policy: ValidationPolicy::StrictOnline,
                now,
                anchors: &pki.anchors,
                intermediates: &[],
                http: &pki.http,
            };
            let network = NetworkPolicy::only_endpoints([
                "http://tsa.synthetic.test",
                "http://ocsp.synthetic.test",
            ])
            .unwrap();
            let services = XadesServices {
                validation: &context,
                network: &network,
                temporary: &store,
                tsa: Some(&pki.tsa),
                material: oncl_pki::cms::ades::ValidationMaterial {
                    certificates: &[],
                    ocsp: &[],
                    crls: &[],
                },
                evidence_limits: None,
                host_clock: None,
            };
            let spec = XadesSpec {
                level,
                tsa: Some(pki.tsa.clone()),
                chain: vec![],
                signature_method: Some(match name {
                    "user-rsa-sign" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    "user-gost2004-sign" => {
                        "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"
                    }
                    _ => {
                        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512"
                    }
                }),
                digest_method: (name == "user-rsa-sign").then_some(
                    "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
                ),
            };
            let mut stage = store.stage(&mut scope).unwrap();
            let mut output = oncl_pki::io::XmlSignatureOutput::new(&mut stage, &scope).unwrap();
            let prepared = oncl_xml::xades::prepare_spec_source(
                Source::sequential(
                    &mut Cursor::new(b"<r xml:lang='kk'><p>protected</p></r>"),
                    None,
                ),
                &spec,
                now,
                &services,
                &mut scope,
            )
            .unwrap();
            let admission_scope = scope.shared_view();
            let mut admission = |bytes| admission_scope.check_output_capacity(bytes);
            let report = prepared
                .sign_transaction(
                    &mut pki.signer,
                    &services,
                    &mut output,
                    &mut scope,
                    &mut admission,
                )
                .unwrap_or_else(|e| panic!("{name}/{level:?}: {e:?}"));
            assert_eq!(report.verification.validation.verdict, Verdict::Valid);
            assert_eq!(report.verification.signatures()[0].level, Some(expected));
            assert!(
                report.verification.signatures()[0]
                    .references()
                    .iter()
                    .all(|r| r.digest_matches)
            );
            output.finish(&scope).unwrap();
        }
    }
}

#[test]
fn bounded_spec_preflights_combined_host_and_request_material_without_encoding_copy() {
    use der::Encode;
    use oncl_pki::{
        cms::ades::ValidationMaterial,
        evidence::{EvidenceError, EvidenceLimits},
    };
    use oncl_xml::xades::{XadesLevel, XadesServices, XadesSpec};
    let pki = Pki::new("user-rsa-sign");
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let now = time::macros::datetime!(2026-11-02 12:00 UTC);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let root = pki.anchors.certs()[0].clone();
    let size = u64::from(u32::from(root.encoded_len().unwrap()));
    for count_limit in [true, false] {
        let cap = ResourceLimits::default();
        let mut scope = Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap();
        let certificates = [root.clone()];
        let services = XadesServices {
            validation: &context,
            network: &network,
            temporary: &store,
            tsa: Some(&pki.tsa),
            material: ValidationMaterial {
                certificates: &certificates,
                ocsp: &[],
                crls: &[],
            },
            evidence_limits: Some(EvidenceLimits {
                max_items: if count_limit { 2 } else { 24 },
                max_bytes: if count_limit { 6291456 } else { size * 2 - 1 },
                max_item_bytes: size,
                max_crl_bytes: if count_limit { 6291456 } else { size * 2 - 1 },
                max_crl_item_bytes: size,
                max_total_bytes: if count_limit { 6291456 } else { size * 2 - 1 },
                max_chain_len: 16,
                max_proofs: 1,
                max_coverage_parts: 256,
                max_coverage_bytes: 1 << 40,
            }),
            host_clock: None,
        };
        let spec = XadesSpec {
            level: XadesLevel::Lt,
            tsa: Some(pki.tsa.clone()),
            chain: vec![root.clone()],
            signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            digest_method: None,
        };
        let error = oncl_xml::xades::prepare_spec_source(
            Source::sequential(&mut Cursor::new(b"<r/>"), None),
            &spec,
            now,
            &services,
            &mut scope,
        )
        .err()
        .expect("combined material must be admitted before capture");
        assert!(matches!(
            error,
            oncl_xml::XmlSourceError::Evidence(EvidenceError::Limit)
        ));
        assert_eq!(scope.progress().bytes_in, 0);
    }
    // Compatibility B/T never serialize this request chain, so its otherwise
    // excessive item size must not become a new preflight rejection.
    for level in [XadesLevel::B, XadesLevel::T] {
        let cap = ResourceLimits::default();
        let mut scope = Arc::new(SharedBudget::new(cap.clone()).unwrap())
            .begin(cap, Arc::new(Control))
            .unwrap();
        let services = XadesServices {
            validation: &context,
            network: &network,
            temporary: &store,
            tsa: Some(&pki.tsa),
            material: ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            evidence_limits: Some(EvidenceLimits {
                max_items: 24,
                max_bytes: 6291456,
                max_item_bytes: size - 1,
                max_crl_bytes: 6291456,
                max_crl_item_bytes: size - 1,
                max_total_bytes: 6291456,
                max_chain_len: 16,
                max_proofs: 1,
                max_coverage_parts: 256,
                max_coverage_bytes: 1 << 40,
            }),
            host_clock: None,
        };
        let spec = XadesSpec {
            level,
            tsa: Some(pki.tsa.clone()),
            chain: vec![root.clone()],
            signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            digest_method: None,
        };
        let prepared = oncl_xml::xades::prepare_spec_source(
            Source::sequential(&mut Cursor::new(b"<r/>"), None),
            &spec,
            now,
            &services,
            &mut scope,
        );
        assert!(
            prepared.is_ok(),
            "ignored B/T chain must preserve compatibility"
        );
    }
}

#[test]
fn wsse_embedding_retains_baseline_properties_and_every_carried_proof_check() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    for level in [AdesLevel::B, AdesLevel::T, AdesLevel::Lt] {
        let mut pki = Pki::new("user-rsa-sign");
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
        let now = time::macros::datetime!(2026-11-02 12:00 UTC);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now,
            anchors: &pki.anchors,
            intermediates: &[],
            http: &pki.http,
        };
        let network = NetworkPolicy::only_endpoints([
            "http://tsa.synthetic.test",
            "http://ocsp.synthetic.test",
        ])
        .unwrap();
        let services = XadesServices {
            validation: &context,
            network: &network,
            temporary: &store,
            tsa: Some(&pki.tsa),
            material: oncl_pki::cms::ades::ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            evidence_limits: None,
            host_clock: None,
        };
        let source = b"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'><s:Header><w:Security xmlns:w='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' u:Id='security'/></s:Header><s:Body u:Id='body'><request>protected</request></s:Body></s:Envelope>";
        let spec = XadesSourceSpec {
            xml: XmlSignProfile {
                target: Some("body"),
                parent: Some("security"),
                signature_id: Some("sig"),
                enveloped: false,
                ..Default::default()
            },
            level,
            signing_time: now,
        };
        let mut bytes = Vec::new();
        let generated = oncl_xml::xades::sign_source(
            Source::sequential(&mut Cursor::new(source), None),
            &spec,
            &mut pki.signer,
            &services,
            &mut bytes,
            &mut scope,
        )
        .unwrap();
        assert_eq!(generated.verification.validation.verdict, Verdict::Valid);
        drop(generated);
        let source = String::from_utf8(bytes).unwrap();
        let parsed = roxmltree::Document::parse(&source).unwrap();
        let info = parsed
            .descendants()
            .find(|n| n.tag_name().name() == "KeyInfo")
            .unwrap();
        let certificate = parsed
            .descendants()
            .find(|n| n.tag_name().name() == "X509Certificate")
            .unwrap()
            .text()
            .unwrap();
        let binding = format!(
            "<ds:KeyInfo><w:SecurityTokenReference xmlns:w='{}'><w:KeyIdentifier EncodingType='{}' ValueType='{}'>{certificate}</w:KeyIdentifier></w:SecurityTokenReference></ds:KeyInfo>",
            oncl_xml::wsse::WSSE_NS,
            oncl_xml::wsse::BASE64_BINARY,
            oncl_xml::wsse::X509_V3
        );
        let embedded = format!(
            "{}{}{}",
            &source[..info.range().start],
            binding,
            &source[info.range().end..]
        );
        let profile = oncl_xml::wsse::WsseVerifyProfile::default();
        let checked = oncl_xml::wsse::verify_source(
            Source::sequential(&mut Cursor::new(&embedded), None),
            &profile,
            &store,
            &context,
            &network,
            &mut scope,
        )
        .unwrap();
        assert_eq!(checked.xml.validation.verdict, Verdict::Valid);
        assert_eq!(checked.xml.minimum_level(), Some(level));
        assert!(checked.signers()[0].body_digest_matches());
        drop(checked);
        let wrong_baseline = embedded.replace(
            "ObjectReference=\"#sig-Reference-0\"",
            "ObjectReference=\"#body\"",
        );
        assert_ne!(wrong_baseline, embedded);
        assert!(
            oncl_xml::wsse::verify_source(
                Source::sequential(&mut Cursor::new(wrong_baseline), None),
                &profile,
                &store,
                &context,
                &network,
                &mut scope
            )
            .is_err()
        );
        if level > AdesLevel::B {
            let damaged = embedded.replace(
                "<xades:EncapsulatedTimeStamp>",
                "<xades:EncapsulatedTimeStamp>AAAA",
            );
            assert_ne!(damaged, embedded);
            let checked = oncl_xml::wsse::verify_source(
                Source::sequential(&mut Cursor::new(damaged), None),
                &profile,
                &store,
                &context,
                &network,
                &mut scope,
            );
            assert!(checked.is_err() || checked.unwrap().xml.validation.verdict != Verdict::Valid);
        }
    }
}

/// A long operation: the validation context and SigningTime are sampled when the operation
/// starts, the trusted host clock, responders and the final verification are hours later.
fn delayed_sign(
    level: oncl_pki::evidence::AdesLevel,
    host_clock_late: bool,
) -> Result<oncl_pki::validation::Verdict, String> {
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let start = time::macros::datetime!(2026-11-02 12:00 UTC);
    let late = start + time::Duration::hours(6);
    let mut pki = Pki::at("user-rsa-sign", late);
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: start,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let clock = move || late;
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: if host_clock_late { Some(&clock) } else { None },
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level,
        signing_time: start,
    };
    let mut bytes = Vec::new();
    oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .map(|r| r.verification.validation.verdict)
    .map_err(|e| format!("{e:?}"))
}

#[test]
fn delayed_operation_signs_with_host_clock_and_fails_closed_with_stale_context() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    for level in [AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta] {
        let ok = delayed_sign(level, true);
        eprintln!("{level:?} host-clock: {ok:?}");
        assert_eq!(ok, Ok(Verdict::Valid), "{level:?}");
        let stale = delayed_sign(level, false);
        eprintln!("{level:?} stale-context: {stale:?}");
        assert!(
            stale.is_err(),
            "{level:?} must not succeed with stale context"
        );
    }
}

/// Same long operation through the prepared path the host (`oncl-core`) uses: preparation and
/// SigningTime at `start`, signing, timestamp and final verification at `late`.
fn delayed_prepared(
    level: oncl_pki::evidence::AdesLevel,
    tsa_hours_before: i64,
) -> Result<oncl_pki::validation::Verdict, String> {
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let start = time::macros::datetime!(2026-11-02 12:00 UTC);
    let late = start + time::Duration::hours(6);
    let mut pki = Pki::at_split(
        "user-rsa-sign",
        late,
        late - time::Duration::hours(tsa_hours_before),
        None,
    );
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: start,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let clock = move || late;
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: Some(&clock),
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level,
        signing_time: start,
    };
    let mut prepared = oncl_xml::xades::prepare_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &store,
        &mut scope,
    )
    .map_err(|e| format!("prepare {e:?}"))?;
    prepared
        .verify_existing_with_clock(&context, &network, &clock, &mut scope)
        .map_err(|e| format!("existing {e:?}"))?;
    let stage_budget = ResourceLimits::default();
    let _ = stage_budget;
    let mut stage = store.stage(&mut scope).map_err(|e| format!("{e:?}"))?;
    let mut output =
        oncl_pki::io::XmlSignatureOutput::new(&mut stage, &scope).map_err(|e| format!("{e:?}"))?;
    let mut resources = scope.shared_view();
    oncl_xml::xades::sign_prepared(
        prepared,
        level,
        start,
        &mut pki.signer,
        &services,
        &mut output,
        &mut resources,
    )
    .map(|r| r.verification.validation.verdict)
    .map_err(|e| format!("{e:?}"))
}

#[test]
fn delayed_prepared_path_signs_with_host_clock() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    for level in [AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta] {
        assert_eq!(delayed_prepared(level, 0), Ok(Verdict::Valid), "{level:?}");
        eprintln!("{level:?} tsa 5h old: {:?}", delayed_prepared(level, 5));
    }
}

#[test]
fn stale_status_after_long_operation_fails_closed_naming_the_check() {
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let start = time::macros::datetime!(2026-11-02 12:00 UTC);
    let late = start + time::Duration::hours(6);
    // The responder answers as of `start` (its answer expired hours ago), the host clock is late.
    let mut pki = Pki::at("user-rsa-sign", start);
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: start,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let clock = move || late;
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: Some(&clock),
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level: oncl_pki::evidence::AdesLevel::T,
        signing_time: start,
    };
    let mut bytes = Vec::new();
    let error = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .map(|_| ())
    .unwrap_err();
    let text = format!("{error:?}");
    eprintln!("stale status: {text}");
    assert!(text.contains("final XAdES validation failed:"), "{text}");
}

/// Run one signature at `level` where every checkpoint of the operation costs `step_seconds` of
/// host time, so document passes take (simulated) minutes. Returns verdict or error text.
fn ticking_sign(
    level: oncl_pki::evidence::AdesLevel,
    step_ms: i64,
) -> Result<oncl_pki::validation::Verdict, String> {
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let start = time::macros::datetime!(2026-11-02 12:00 UTC);
    let ticking = Ticking::new(start, time::Duration::milliseconds(step_ms));
    let clock: Clock = {
        let t = ticking.clone();
        Arc::new(move || t.read())
    };
    let mut pki = Pki::live("user-rsa-sign", clock.clone());
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, ticking.clone()).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: start,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let host = clock.clone();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: Some(&*host),
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level,
        signing_time: start,
    };
    let mut bytes = Vec::new();
    oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .map(|r| r.verification.validation.verdict)
    .map_err(|e| format!("{e:?}"))
}

#[test]
fn long_document_passes_do_not_age_the_status_checked_after_them() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    // Each checkpoint costs 1 s of host time: the carried-proof passes between the context
    // sample and the status check last several times the 300 s OCSP window (verified RED
    // without the fresh sample), the evidence steps themselves stay far below it.
    assert_eq!(ticking_sign(AdesLevel::T, 1000), Ok(Verdict::Valid));
}

/// D3: NCANode/Kalkan writes `SigningCertificateV2/CertDigest` with the GOST R 34.11-2015
/// digest for a GOST key. The strict XAdES structure check refused every level of that
/// real output (`InvalidInput`) although the RSA/SHA-256 shape verified. The pinned
/// fixtures are NCANode's own GOST 2015 documents (fetched, not committed).
#[test]
fn ncanode_gost_xades_with_a_gost_certificate_digest_is_structurally_accepted() {
    use oncl_pki::evidence::AdesLevel;
    for (level, expected) in [
        ("b", AdesLevel::B),
        ("t", AdesLevel::T),
        ("lt", AdesLevel::Lt),
        ("lta", AdesLevel::Lta),
    ] {
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
        let anchors = oncl_pki::pkix::CaSet::new(vec![]);
        let ctx = ValidationContext {
            policy: ValidationPolicy::OfflineReport,
            now: time::macros::datetime!(2026-11-02 12:00 UTC),
            anchors: &anchors,
            intermediates: &[],
            http: &Offline,
        };
        let xml = read(oncl_testkit::ncanode(&format!(
            "xades-test-signed-{level}.xml"
        )));
        let verification = verify_source(
            Source::sequential(&mut Cursor::new(xml), None),
            &XmlVerifyProfile {
                required_level: Some(AdesLevel::B),
                ..Default::default()
            },
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut scope,
        )
        .unwrap_or_else(|error| panic!("{level}: {error:?}"));
        let signers = verification.facts.signatures();
        assert_eq!(signers.len(), 1, "{level}");
        assert!(
            signers[0]
                .references()
                .iter()
                .all(|reference| reference.digest_matches),
            "{level}"
        );
        // Chain trust is absent here, so the verdict is not Valid; but the level the
        // structure carries must never exceed the evidence the document holds.
        assert!(
            signers[0].level.is_some_and(|l| l <= expected),
            "{level}: {:?}",
            signers[0].level
        );
    }
}

// ---- LT/LTA: embedded status is judged at the proof time, not at the wall clock ----------

const T0: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);

/// Sign at `level` as of `sign_now` (the proof is minted by the world's TSA at its fixed
/// genTime), returning the document and the verdict of the signing itself.
fn lt_sign(
    pki: &mut Pki,
    level: oncl_pki::evidence::AdesLevel,
    sign_now: time::OffsetDateTime,
) -> Result<(Vec<u8>, oncl_pki::validation::Verdict), String> {
    use oncl_xml::xades::{XadesServices, XadesSourceSpec};
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: sign_now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let services = XadesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        tsa: Some(&pki.tsa),
        material: oncl_pki::cms::ades::ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &[],
        },
        evidence_limits: None,
        host_clock: None,
    };
    let spec = XadesSourceSpec {
        xml: XmlSignProfile {
            target: Some("p"),
            parent: Some("s"),
            signature_id: Some("sig"),
            ..Default::default()
        },
        level,
        signing_time: T0,
    };
    let mut bytes = Vec::new();
    let result = oncl_xml::xades::sign_source(
        Source::sequential(
            &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
            None,
        ),
        &spec,
        &mut pki.signer,
        &services,
        &mut bytes,
        &mut scope,
    )
    .map_err(|e| format!("{e:?}"))?;
    let verdict = result.verification.validation.verdict;
    drop(result);
    Ok((bytes, verdict))
}

/// Verify a document with the host clock at `now`, offline-capable strict policy.
fn lt_verify(
    pki: &Pki,
    bytes: &[u8],
    now: time::OffsetDateTime,
    policy: ValidationPolicy,
) -> (
    oncl_pki::validation::Verdict,
    oncl_pki::validation::CheckStatus,
    oncl_pki::validation::CheckStatus,
) {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let context = ValidationContext {
        policy,
        now,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &pki.http,
    };
    let network =
        NetworkPolicy::only_endpoints(["http://tsa.synthetic.test", "http://ocsp.synthetic.test"])
            .unwrap();
    let report = verify_source(
        Source::sequential(&mut Cursor::new(bytes.to_vec()), None),
        &XmlVerifyProfile::default(),
        &store,
        &context,
        &network,
        &mut scope,
    )
    .unwrap();
    let signer = &report.validation.signers[0];
    (
        report.validation.verdict,
        signer.revocation,
        signer.timestamp,
    )
}

#[test]
fn lt_and_lta_embedded_status_is_judged_at_the_proof_time_not_now() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    for level in [AdesLevel::Lt, AdesLevel::Lta] {
        let mut pki = Pki::at("user-rsa-sign", T0);
        let (bytes, signed) = lt_sign(&mut pki, level, T0).unwrap();
        assert_eq!(signed, Verdict::Valid, "{level:?} at signing");
        for (label, delta) in [
            ("+0", time::Duration::ZERO),
            ("+6m", time::Duration::minutes(6)),
            ("+1h", time::Duration::HOUR),
            ("+1d", time::Duration::DAY),
            ("+400d", time::Duration::days(400)),
        ] {
            for policy in [
                ValidationPolicy::StrictOnline,
                ValidationPolicy::OfflineReport,
            ] {
                let (verdict, revocation, timestamp) = lt_verify(&pki, &bytes, T0 + delta, policy);
                assert_eq!(
                    verdict,
                    Verdict::Valid,
                    "{level:?} {label} {policy:?}: revocation {revocation:?} timestamp {timestamp:?}"
                );
            }
        }
    }
}

fn serial_hex(key: &oncl_pki::pkcs12::KeyEntry) -> String {
    key.cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every control case must not be Valid at any verification time (signing may itself
/// already refuse it: then the case is rejected at signing).
fn lt_control_never_valid(
    label: &str,
    pki: &mut Pki,
    level: oncl_pki::evidence::AdesLevel,
    sign_now: time::OffsetDateTime,
) {
    use oncl_pki::validation::Verdict;
    let Ok((bytes, signed)) = lt_sign(pki, level, sign_now) else {
        return;
    };
    if signed == Verdict::Valid {
        // Sign-time evidence is judged as Valid there: it must be judged so only if the
        // evidence is in order at every later time too, so verify later.
    }
    for delta in [
        time::Duration::ZERO,
        time::Duration::HOUR,
        time::Duration::DAY,
    ] {
        let (verdict, ..) = lt_verify(pki, &bytes, T0 + delta, ValidationPolicy::StrictOnline);
        assert_ne!(verdict, Verdict::Valid, "{label} {level:?} +{delta}");
    }
}

#[test]
fn lt_lta_control_cases_stay_rejected_at_proof_time() {
    use oncl_pki::{
        evidence::AdesLevel,
        ocsp::{CertStatus, MockOcsp, OcspTamper},
    };
    for level in [AdesLevel::Lt, AdesLevel::Lta] {
        // Stale at signing: issued two hours before the proof.
        let mut pki = Pki::at("user-rsa-sign", T0)
            .with_ocsp(|r, _| MockOcsp::new(r).with_now(T0).tamper(OcspTamper::Stale));
        lt_control_never_valid("stale", &mut pki, level, T0);
        // From the future of the verifier: minted two hours after the proof, verified
        // an hour after it.
        let mut pki = Pki::at_split("user-rsa-sign", T0 + time::Duration::hours(2), T0, None);
        let (bytes, signed) = lt_sign(&mut pki, level, T0 + time::Duration::hours(2)).unwrap();
        assert_eq!(
            signed,
            oncl_pki::validation::Verdict::Valid,
            "future fixture signs"
        );
        let (verdict, ..) = lt_verify(
            &pki,
            &bytes,
            T0 + time::Duration::HOUR,
            ValidationPolicy::StrictOnline,
        );
        assert_ne!(
            verdict,
            oncl_pki::validation::Verdict::Valid,
            "future {level:?}"
        );
        // Revoked at the proof time (ten minutes before it).
        let mut pki = Pki::at("user-rsa-sign", T0);
        let hex = serial_hex(&pki.signer);
        let mut pki = {
            pki = pki.with_ocsp(move |r, _| {
                MockOcsp::new(r).with_now(T0).status(
                    &hex,
                    CertStatus::Revoked {
                        time: T0 - time::Duration::minutes(10),
                        reason: None,
                    },
                )
            });
            pki
        };
        lt_control_never_valid("revoked at P", &mut pki, level, T0);
        // The response's signature is wrong, the CertID is another certificate's, the
        // responder is not an OCSP responder.
        for (label, tamper) in [
            ("bad signature", Some(OcspTamper::WrongKey)),
            ("wrong CertID", Some(OcspTamper::OtherCertId)),
            ("not authorized", None),
        ] {
            let mut pki = Pki::at("user-rsa-sign", T0).with_ocsp(move |r, tsa| match tamper {
                Some(tamper) => MockOcsp::new(r).with_now(T0).tamper(tamper),
                None => MockOcsp::new(tsa).with_now(T0),
            });
            lt_control_never_valid(label, &mut pki, level, T0);
        }
    }
}

#[test]
fn xades_lt_with_damaged_embedded_status_is_not_valid_an_hour_later() {
    use oncl_pki::{evidence::AdesLevel, validation::Verdict};
    let mut pki = Pki::at("user-rsa-sign", T0);
    let (bytes, _) = lt_sign(&mut pki, AdesLevel::Lt, T0).unwrap();
    let hour = T0 + time::Duration::HOUR;
    assert_eq!(
        lt_verify(&pki, &bytes, hour, ValidationPolicy::StrictOnline).0,
        Verdict::Valid
    );
    let mut text = String::from_utf8(bytes).unwrap();
    let start =
        text.find("<xades:EncapsulatedOCSPValue>").unwrap() + "<xades:EncapsulatedOCSPValue>".len();
    let byte = if &text[start..start + 1] == "A" {
        "B"
    } else {
        "A"
    };
    text.replace_range(start..start + 1, byte);
    for now in [T0, hour] {
        let (verdict, ..) = lt_verify(&pki, text.as_bytes(), now, ValidationPolicy::StrictOnline);
        assert_ne!(verdict, Verdict::Valid, "{now}");
    }
}
