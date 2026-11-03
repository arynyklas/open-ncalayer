//! P03 public artifacts: actual Engine operations and loopback TSA/OCSP/CRL.
use super::*;
use der::Encode;
use oncl_core::{
    CadesConfiguration, ExtendRequest, SignRequest, VerifyRequest,
    keys::{
        KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
    },
};
use oncl_pki::{
    cms::ades::ValidationMaterial,
    evidence::{AdesLevel, EvidenceLimits},
    http::{GetOptions, HttpRequest, HttpTransport, ProxySetting, UreqTransport},
    io::TemporaryStore,
    key::PrivateKey,
    pkix::CaSet,
    testing::{TestCertSpec, issue_cert},
    tsp::{MockTsa, TsaMethod, TsaProfile, TsaSpec},
    validation::{NetworkPolicy, Verdict},
};
use std::{
    io::{Cursor, Read, Write},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}
fn leaf(
    mut key: oncl_pki::pkcs12::KeyEntry,
    template: &str,
    serial: u8,
    root: &oncl_pki::pkcs12::KeyEntry,
    ocsp: &str,
    crl: &str,
) -> oncl_pki::pkcs12::KeyEntry {
    let mut spec = TestCertSpec::from_cert(&fixture_entry(template).cert);
    strip(&mut spec);
    spec.public_key = key.key.public_key().to_spki();
    spec.serial = vec![0x63, 0x17, serial];
    spec.extensions.extend(
        TestCertSpec::from_cert(&fixture_entry("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    key.cert = issue_cert(root, spec);
    issue_local(key, root, ocsp, crl)
}
fn selector(key: &oncl_pki::pkcs12::KeyEntry) -> Result<KeySelector, Box<dyn std::error::Error>> {
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: key.alias.clone(),
            pkcs8_der: key.key.to_pkcs8_der()?.to_vec(),
            cert_der: Some(key.cert.to_der()?),
        }],
        &[],
        "P03 synthetic",
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x17),
    )?;
    Ok(KeySelector::inline(bytes, None))
}
struct Consent {
    keys: Vec<oncl_core::keys::KeyId>,
    calls: AtomicUsize,
}
impl KeyUseGuard for Consent {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, oncl_core::OperationError> {
        if event.action != Action::Sign || !self.keys.contains(&event.key_id) {
            return Err(oncl_core::OperationError::PermissionDenied);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
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
fn server(
    listener: std::net::TcpListener,
    origin: String,
    tsa: Arc<dyn HttpTransport>,
    ocsp: Arc<dyn HttpTransport>,
    crl: Arc<dyn HttpTransport>,
    calls: Arc<AtomicUsize>,
) -> EvidenceProbeServer {
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        let start = std::time::Instant::now();
        while !stopped.load(Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(180)
        {
            let (mut socket, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                Err(e) => return Err(e.to_string()),
            };
            if calls.fetch_add(1, Ordering::SeqCst) >= 2048 {
                return Err("P03 HTTP fixture request limit".into());
            }
            socket.set_nonblocking(false).map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            let end = loop {
                let n = socket.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 || bytes.len() + n > 65536 {
                    return Err("P03 incomplete request".into());
                }
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let head = std::str::from_utf8(&bytes[..end])
                .map_err(|e| e.to_string())?
                .to_owned();
            let mut length = None;
            let mut content_type = None;
            for line in head.lines().skip(1) {
                if let Some((key, value)) = line.split_once(':') {
                    if key.eq_ignore_ascii_case("content-length") {
                        if length.is_some() {
                            return Err("duplicate Content-Length".into());
                        }
                        length = Some(value.trim().parse::<usize>().map_err(|e| e.to_string())?);
                    }
                    if key.eq_ignore_ascii_case("content-type") {
                        content_type = Some(value.trim());
                    }
                }
            }
            let length = length.unwrap_or(0);
            if length > 65536 - end {
                return Err("P03 oversized request".into());
            }
            while bytes.len() - end < length {
                let n = socket.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 || bytes.len() + n > 65536 {
                    return Err("P03 short request body".into());
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
            let mut first = head
                .lines()
                .next()
                .ok_or("missing request line")?
                .split_whitespace();
            let method = first.next().ok_or("missing method")?;
            let path = first.next().ok_or("missing path")?;
            let url = format!("{origin}{path}");
            let request = match method {
                "POST" => HttpRequest::post(
                    &url,
                    content_type,
                    &bytes[end..end + length],
                    GetOptions::default(),
                ),
                "GET" => HttpRequest::get(&url, GetOptions::default()),
                _ => return Err("P03 method".into()),
            };
            let reply = if path == "/tsa" {
                tsa.send(&request)
            } else if path == "/root.crl" {
                crl.send(&request)
            } else if path.starts_with("/ocsp") {
                ocsp.send(&request)
            } else {
                return Err("P03 route".into());
            }
            .map_err(|e| e.to_string())?;
            write!(socket,"HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.status,reply.content_type.as_deref().unwrap_or("application/octet-stream"),reply.body.len()).map_err(|e|e.to_string())?;
            socket.write_all(&reply.body).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    EvidenceProbeServer {
        stop,
        thread: Some(thread),
    }
}
fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 128,
        max_bytes: 16 << 20,
        max_item_bytes: 2 << 20,
        max_chain_len: 8,
        max_proofs: 16,
        max_coverage_parts: 4096,
        max_coverage_bytes: 10_737_418_240,
    }
}
fn begin(
    engine: &Engine,
    action: Action,
    key: Option<&KeySelector>,
) -> Result<oncl_core::OperationContext, oncl_core::OperationError> {
    let grant = ExecutionGrant::new([action]);
    let grant = if let Some(key) = key {
        grant.with_keys([key.key_id()])
    } else {
        grant
    };
    engine.begin(grant, OperationPolicy::strict_online(), Arc::new(Control))
}
fn verify(
    engine: &Engine,
    bytes: &[u8],
    required: AdesLevel,
) -> Result<oncl_core::VerificationReport, oncl_core::OperationError> {
    engine.verify(
        &VerifyRequest::pades(required, evidence_limits()),
        Source::sequential(&mut Cursor::new(bytes), None),
        None,
        &mut begin(engine, Action::Verify, None)?,
    )
}
fn sign(
    engine: &Engine,
    key: &KeySelector,
    input: &[u8],
    level: AdesLevel,
    material: ValidationMaterial<'_>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let report = engine.sign(
        SignRequest::pades(
            KeyRequest::new(key, Some("P03 synthetic")),
            oncl_pdf::PdfSignProfile::default(),
            level,
            material,
            evidence_limits(),
        ),
        Source::sequential(&mut Cursor::new(input), None),
        &mut output,
        &mut begin(engine, Action::Sign, Some(key))?,
    )?;
    if report.applied != oncl_core::keys::AppliedState::Applied
        || report.bytes_in != input.len() as u64
        || report.bytes_out != output.len() as u64
    {
        return Err("P03 private state or single-count I/O mismatch".into());
    }
    Ok(output)
}
fn extend(
    engine: &Engine,
    input: &[u8],
    level: AdesLevel,
    material: ValidationMaterial<'_>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let request = ExtendRequest::pdf(level, oncl_pdf::PdfLimits::default())
        .with_evidence_limits(evidence_limits())
        .with_material(material);
    let report = engine.extend(
        &request,
        Source::sequential(&mut Cursor::new(input), None),
        &mut output,
        &mut begin(engine, Action::Extend, None)?,
    )?;
    if report.applied != oncl_core::keys::AppliedState::NotApplied
        || report.bytes_in != input.len() as u64
        || report.bytes_out != output.len() as u64
        || !output.starts_with(input)
    {
        return Err("P03 evidence-only immutable extension/I/O mismatch".into());
    }
    Ok(output)
}
pub(super) fn run(out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    let scratch = tempfile::tempdir()?;
    let store = TemporaryStore::new(scratch.path())?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = format!("http://{}", listener.local_addr()?);
    let ocsp_url = format!("{origin}/ocsp");
    let crl_url = format!("{origin}/root.crl");
    let mut root = fixture_entry("user-rsa-sign");
    root.key = PrivateKey::from_pkcs8_der(
        include_bytes!("../../../../fixtures/openssl/rsa.pk8.der"),
        None,
    )?;
    root.cert = fixture_entry("root-gost2015.key").cert;
    let mut spec = TestCertSpec::from_cert(&root.cert);
    strip(&mut spec);
    spec.public_key = root.key.public_key().to_spki();
    spec.serial = vec![0x63, 0x17, 1];
    root.cert = issue_cert(&root, spec);
    let doc = leaf(
        fixture_entry("user-rsa-sign"),
        "user-rsa-sign",
        2,
        &root,
        &ocsp_url,
        &crl_url,
    );
    let tsa = leaf(doc.clone(), "tsa-gost2015", 3, &root, &ocsp_url, &crl_url);
    let responder = leaf(doc.clone(), "ocsp-gost2015", 4, &root, &ocsp_url, &crl_url);
    let mut second = doc.clone();
    second.key = root.key.clone();
    let second = leaf(second, "user-rsa-sign", 5, &root, &ocsp_url, &crl_url);
    let gost2004 = leaf(
        fixture_entry("user-gost2004-sign"),
        "user-gost2004-sign",
        6,
        &root,
        &ocsp_url,
        &crl_url,
    );
    let gost2015 = leaf(
        fixture_entry("user-gost2015-sign"),
        "user-gost2015-sign",
        7,
        &root,
        &ocsp_url,
        &crl_url,
    );
    let crl_http = oncl_pki::crl::MockCrl::new(root.clone())
        .with_this_update(FIXED_NOW - time::Duration::MINUTE)
        .next_update(Some(FIXED_NOW + time::Duration::HOUR));
    let crl = crl_http.der();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server(
        listener,
        origin.clone(),
        Arc::new(MockTsa::new(tsa.clone()).with_gen_time(FIXED_NOW)),
        Arc::new(oncl_pki::ocsp::MockOcsp::new(responder).with_now(FIXED_NOW)),
        Arc::new(crl_http),
        calls.clone(),
    );
    let transport = Arc::new(UreqTransport::with_proxy(ProxySetting::None));
    let network = NetworkPolicy::only_endpoints([origin.as_str()])?;
    let ocsp = transport
        .send(&HttpRequest::post(
            &ocsp_url,
            Some("application/ocsp-request"),
            &oncl_pki::ocsp::request_der(&doc.cert, &root.cert),
            GetOptions::default(),
        ))?
        .body;
    let mut profile = TsaProfile::kalkan_default();
    profile.url = format!("{origin}/tsa");
    profile.method = TsaMethod::Post;
    let mut profile = TsaSpec::from(profile);
    profile.check_skew = None;
    let keys = [
        selector(&doc)?,
        selector(&second)?,
        selector(&gost2004)?,
        selector(&gost2015)?,
    ];
    let guard = Arc::new(Consent {
        keys: keys.iter().map(|k| k.key_id()).collect(),
        calls: AtomicUsize::new(0),
    });
    let validation = || {
        oncl_core::ValidationServices::new(
            CaSet::new(vec![root.cert.clone()]),
            vec![],
            transport.clone(),
            network.clone(),
            Arc::new(|| FIXED_NOW),
        )
    };
    let services = EngineServices::hash_only(ResourceLimits::default())
        .with_temporary_store(store.clone())
        .with_validation(validation())
        .with_cades(CadesConfiguration::new(evidence_limits(), profile.clone()));
    let signer = Engine::new(services.with_keys(Arc::new(KeySources::default()), guard.clone()))?;
    // The actual extension engine has no KeyProvider or KeyUseGuard at all.
    let evidence = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(store)
            .with_validation(validation())
            .with_cades(CadesConfiguration::new(evidence_limits(), profile)),
    )?;
    let certs = [root.cert.clone(), tsa.cert.clone()];
    let crls = [crl.as_slice()];
    let ocsps = [ocsp.as_slice()];
    let material = || ValidationMaterial {
        certificates: &certs,
        ocsp: &ocsps,
        crls: &crls,
    };
    let source = include_bytes!("../../../oncl-pdf/tests/fixtures/external-multipage.pdf");
    std::fs::write(out.join("source.pdf"), source)?;
    for (name, cert) in [
        ("root.der", &root.cert),
        ("tsa.der", &tsa.cert),
        ("signer.der", &doc.cert),
    ] {
        std::fs::write(out.join(name), cert.to_der()?)?;
    }
    std::fs::write(out.join("status.crl.der"), &crl)?;
    std::fs::write(out.join("status.ocsp.der"), &ocsp)?;
    let mut summary = String::from(
        "case=P03\nprofile=EN319142-1 V1.2.1 5.4.2/5.4.3/6.3 n,q,r-y\nprivate_material=none\n",
    );
    {
        let anchors = CaSet::new(vec![root.cert.clone()]);
        let budget = Arc::new(oncl_pki::resource::SharedBudget::new(
            ResourceLimits::default(),
        )?);
        let scope = budget.begin(ResourceLimits::default(), Arc::new(Control))?;
        let http =
            oncl_pki::http::deadline::DeadlineTransport::new(transport.as_ref(), &network, &scope);
        let context = oncl_pki::validation::ValidationContext {
            policy: oncl_pki::validation::ValidationPolicy::StrictOnline,
            now: FIXED_NOW,
            anchors: &anchors,
            intermediates: &[],
            http: &http,
        };
        let checked =
            oncl_pki::validation::validate_certificate(&doc.cert, FIXED_NOW, &context, &[]);
        http.finish()?;
        if checked.verdict() != Verdict::Valid {
            return Err(format!("P03 fixture preflight: {checked:?}").into());
        }
    }
    let mut rsa_b = Vec::new();
    let mut rsa_lta = Vec::new();
    for (index, label) in [(0, "rsa"), (2, "gost2004"), (3, "gost2015-512")] {
        let b = sign(&signer, &keys[index], source, AdesLevel::B, material())?;
        if index == 0 {
            rsa_b = b.clone();
        }
        let t = sign(&signer, &keys[index], source, AdesLevel::T, material())?;
        let lt = extend(&evidence, &t, AdesLevel::Lt, material())?;
        let lta = extend(&evidence, &lt, AdesLevel::Lta, material())?;
        let renewal = extend(&evidence, &lta, AdesLevel::Lta, material())?;
        for (level, name, bytes) in [
            (AdesLevel::B, "B", &b),
            (AdesLevel::T, "T", &t),
            (AdesLevel::Lt, "Lt", &lt),
            (AdesLevel::Lta, "Lta", &lta),
            (AdesLevel::Lta, "Renewed-Lta", &renewal),
        ] {
            let report = verify(&evidence, bytes, level)?;
            if report.verdict != Verdict::Valid || report.ades_level != Some(level) {
                return Err(format!("P03 {label}-{name}: {report:?}").into());
            }
            std::fs::write(out.join(format!("{label}-{name}.pdf")), bytes)?;
            summary.push_str(&format!(
                "{label}-{name}=Valid {:?} bytes={} signers={}\n",
                report.ades_level,
                bytes.len(),
                report.signers.len()
            ));
        }
        if index == 0 {
            rsa_lta = lta;
        }
    }
    let ext_t = extend(&evidence, &rsa_b, AdesLevel::T, material())?;
    let report = verify(&evidence, &ext_t, AdesLevel::T)?;
    if report.verdict != Verdict::Valid {
        return Err("P03 B-to-T failed".into());
    }
    std::fs::write(out.join("rsa-B-Extended-T.pdf"), &ext_t)?;
    drop(report);
    let two = sign(&signer, &keys[1], &rsa_lta, AdesLevel::Lta, material())?;
    let report = verify(&evidence, &two, AdesLevel::Lta)?;
    if report.signers.len() != 2
        || report.ades_level != Some(AdesLevel::Lta)
        || !two.starts_with(&rsa_lta)
    {
        return Err("P03 multiple signer archive failed".into());
    }
    std::fs::write(out.join("rsa-Multiple-Lta.pdf"), &two)?;
    drop(report);
    let before = guard.calls.load(Ordering::SeqCst);
    let mut dss = rsa_lta.clone();
    let at = dss
        .windows(crl.len())
        .position(|b| b == crl)
        .ok_or("missing actual DSS CRL")?;
    dss[at + crl.len() - 1] ^= 1;
    let mut timestamp = rsa_lta.clone();
    let at = timestamp
        .windows(b"/ETSI.RFC3161".len())
        .position(|b| b == b"/ETSI.RFC3161")
        .ok_or("missing document timestamp")?;
    let gap = at
        + timestamp[at..]
            .windows(11)
            .position(|b| b == b"/Contents <")
            .ok_or("missing physical timestamp contents")?
        + 11;
    let end = gap
        + timestamp[gap..]
            .iter()
            .position(|b| *b == b'>')
            .ok_or("unterminated timestamp")?;
    let mut token = Vec::new();
    oncl_pki::io::decode_pdf_byte_string(&timestamp[gap - 1..=end], &mut token)?;
    let signature_last = gap + 2 * (oncl_pki::io::padded_der_sequence(&token)?.len() - 1);
    timestamp[signature_last] = if timestamp[signature_last] == b'0' {
        b'1'
    } else {
        b'0'
    };
    for (name, bytes) in [
        ("negative-dss.pdf", dss),
        ("negative-doctimestamp.pdf", timestamp),
    ] {
        if verify(&evidence, &bytes, AdesLevel::B).is_ok_and(|r| r.verdict == Verdict::Valid) {
            return Err("P03 bad proof was laundered as B".into());
        }
        if extend(&evidence, &bytes, AdesLevel::Lta, material()).is_ok() {
            return Err("P03 bad proof was laundered by renewal".into());
        }
        std::fs::write(out.join(name), bytes)?;
        summary.push_str(&format!("{name}=Rejected B-and-renewal\n"));
    }
    if guard.calls.load(Ordering::SeqCst) != before || before != 7 {
        return Err(format!("P03 unexpected private operations {before}").into());
    }
    summary.push_str(&format!("user_private_applications={before}\nextend_key_provider=absent\nloopback_http_requests={}\ninput_source_bytes={}\n",calls.load(Ordering::SeqCst),source.len()));
    server.finish()?;
    std::fs::write(out.join("P03-report.txt"), &summary)?;
    println!("{summary}");
    Ok(())
}
