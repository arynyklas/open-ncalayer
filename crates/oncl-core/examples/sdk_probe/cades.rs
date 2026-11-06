//! Public synthetic CAdES artifacts; private fixture material never leaves scratch.
use super::*;
use der::{Decode, Encode};
use oncl_pki::{
    cert::Certificate,
    cms::ades::{self, AdesServices, ValidationMaterial},
    evidence::{AdesLevel, EvidenceLimits},
    http::{GetOptions, HttpRequest, HttpTransport, ProxySetting, UreqTransport},
    io::TemporaryStore,
    key::{PrivateKey, SigAlg},
    pkix::CaSet,
    resource::SharedBudget,
    testing::{TestCertSpec, issue_cert},
    tsp::{MockTsa, TsaMethod, TsaProfile, TsaSpec},
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use std::{
    io::{Cursor, Read, Write},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|ext| {
        !matches!(
            ext.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}
fn status_extensions(spec: &mut TestCertSpec) {
    spec.extensions.extend(
        TestCertSpec::from_cert(&fixture_entry("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|ext| {
                matches!(
                    ext.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
}
fn selector(
    entry: &oncl_pki::pkcs12::KeyEntry,
) -> Result<oncl_core::keys::KeySelector, Box<dyn std::error::Error>> {
    let container = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry.key.to_pkcs8_der()?.to_vec(),
            cert_der: Some(entry.cert.to_der()?),
        }],
        &[],
        "C03 synthetic",
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x63),
    )?;
    Ok(oncl_core::keys::KeySelector::inline(container, None))
}
struct Consent {
    keys: Vec<oncl_core::keys::KeyId>,
    calls: AtomicUsize,
}
impl oncl_core::keys::KeyUseGuard for Consent {
    fn before_use(
        &self,
        event: &oncl_core::keys::KeyUseEvent,
    ) -> Result<oncl_core::keys::KeyUseReceipt, oncl_core::OperationError> {
        if event.action != Action::Sign || !self.keys.contains(&event.key_id) {
            return Err(oncl_core::OperationError::PermissionDenied);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(oncl_core::keys::KeyUseReceipt::new(event.clone()))
    }
    fn finish(
        &self,
        _: oncl_core::keys::KeyUseReceipt,
        outcome: oncl_core::keys::KeyUseOutcome,
    ) -> Result<(), oncl_core::OperationError> {
        if outcome.succeeded && outcome.applied != oncl_core::keys::AppliedState::Applied {
            return Err(oncl_core::OperationError::AuditFailed);
        }
        Ok(())
    }
}
// Fixture-only slicing preserves received TLVs, including legal nonminimal BER
// length octets. It does not replace the SDK's bounded streaming parser.
fn children(bytes: &[u8]) -> Result<Vec<&[u8]>, Box<dyn std::error::Error>> {
    fn frame(bytes: &[u8], at: usize) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let length = *bytes
            .get(at.checked_add(1).ok_or("fixture offset overflow")?)
            .ok_or("short fixture length")?;
        let (header, len) = if length < 128 {
            (at + 2, length as usize)
        } else {
            let count = (length & 127) as usize;
            if !(1..=8).contains(&count) {
                return Err("unsupported fixture length".into());
            }
            let lengths = bytes
                .get(at + 2..at + 2 + count)
                .ok_or("short fixture length")?;
            let mut len = 0usize;
            for byte in lengths {
                len = len
                    .checked_mul(256)
                    .and_then(|len| len.checked_add(*byte as usize))
                    .ok_or("fixture length overflow")?;
            }
            (at + 2 + count, len)
        };
        let end = header.checked_add(len).ok_or("fixture end overflow")?;
        if end > bytes.len() {
            return Err("short fixture value".into());
        }
        Ok((header, end))
    }
    if bytes.len() > 16 << 20 {
        return Err("fixture metadata cap".into());
    }
    let (mut at, end) = frame(bytes, 0)?;
    if end != bytes.len() {
        return Err("trailing fixture value".into());
    }
    let mut values = Vec::new();
    while at < end {
        let (_, next) = frame(bytes, at)?;
        values.push(&bytes[at..next]);
        at = next;
    }
    Ok(values)
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if body.len() < 128 {
        output.push(body.len() as u8);
    } else {
        let length = body.len().to_be_bytes();
        let bytes = &length[length
            .iter()
            .position(|byte| *byte != 0)
            .expect("nonzero length")..];
        output.push(0x80 | bytes.len() as u8);
        output.extend_from_slice(bytes);
    }
    output.extend_from_slice(body);
    output
}
fn changed_content_type(source: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ci = children(source)?;
    let explicit = children(ci[1])?;
    let mut data = children(explicit[0])?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let mut encap = children(&data[2])?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if encap[0][0] != 6 || encap[0][1] >= 128 {
        return Err("fixture content type is not short-form OID".into());
    }
    encap[0].insert(1, 0x81);
    data[2] = tlv(0x30, &encap.concat());
    Ok(tlv(
        0x30,
        &[ci[0], &tlv(0xa0, &tlv(0x30, &data.concat()))].concat(),
    ))
}
fn reissue_archives(
    source: &[u8],
    document: &[u8],
    outer: HashAlg,
    spec: &TsaSpec,
    http: &dyn HttpTransport,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use oncl_pki::digest::HashState;
    let ci = children(source)?;
    let explicit = children(ci[1])?;
    let mut data = children(explicit[0])?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let content_type = children(&data[2])?[0].to_vec();
    let mut infos = children(data.last().ok_or("missing fixture signers")?)?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    for info in &mut infos {
        let mut fields = children(info)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let mut attrs = children(&fields[6])?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        for attr in &mut attrs {
            let af = children(attr)?;
            let oid: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::from_der(af[0])?;
            if oid.to_string() != "0.4.0.1733.2.4" {
                continue;
            }
            let old = children(af[1])?[0];
            let tc = children(old)?;
            let te = children(tc[1])?;
            let td = children(te[0])?;
            let old_infos = children(td.last().ok_or("missing fixture TSA signer")?)?;
            let ts = children(old_infos[0])?;
            let index_attr = children(ts[6])?[0];
            let ia = children(index_attr)?;
            let index = children(ia[1])?[0];
            let mut content_hash = HashState::new(HashAlg::Sha256);
            content_hash.update(document);
            let mut hash = HashState::new(outer);
            hash.update(&content_type);
            hash.update(content_hash.finish().as_bytes());
            for field in &fields[..6] {
                hash.update(field);
            }
            hash.update(index);
            let mut requested = spec.clone();
            requested.hash = outer;
            let token = oncl_pki::tsp::request(&requested, hash.finish().as_bytes(), http)?.token;
            let nc = children(&token)?;
            let ne = children(nc[1])?;
            let mut nd = children(ne[0])?
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>();
            let new_infos = children(nd.last().ok_or("missing new TSA signer")?)?;
            let mut ns = children(new_infos[0])?
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>();
            if ns.len() != 6 {
                return Err("unexpected fixture TSA unsigned values".into());
            }
            ns.push(tlv(0xa1, index_attr));
            let last = nd.len() - 1;
            nd[last] = tlv(0x31, &tlv(0x30, &ns.concat()));
            let token = tlv(
                0x30,
                &[nc[0], &tlv(0xa0, &tlv(0x30, &nd.concat()))].concat(),
            );
            *attr = tlv(0x30, &[af[0], &tlv(0x31, &token)].concat());
        }
        fields[6] = tlv(0xa1, &attrs.concat());
        *info = tlv(0x30, &fields.concat());
    }
    let last = data.len() - 1;
    data[last] = tlv(0x31, &infos.concat());
    Ok(tlv(
        0x30,
        &[ci[0], &tlv(0xa0, &tlv(0x30, &data.concat()))].concat(),
    ))
}
fn tokens(cms: &[u8]) -> Result<Vec<&[u8]>, Box<dyn std::error::Error>> {
    let ci = children(cms)?;
    let explicit = children(ci[1])?;
    let data = children(explicit[0])?;
    let mut tokens = Vec::new();
    for signer in children(data.last().ok_or("missing signers")?)? {
        let fields = children(signer)?;
        if let Some(attrs) = fields.get(6) {
            for attr in children(attrs)? {
                let fields = children(attr)?;
                let oid: der::asn1::ObjectIdentifier =
                    der::asn1::ObjectIdentifier::from_der(fields[0])?;
                let oid = oid.to_string();
                if oid == "1.2.840.113549.1.9.16.2.14" || oid == "0.4.0.1733.2.4" {
                    tokens.extend(children(fields[1])?);
                }
            }
        }
    }
    Ok(tokens)
}

pub(super) fn run(out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    let scratch = tempfile::tempdir()?;
    let store = TemporaryStore::new(scratch.path())?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = format!("http://{}", listener.local_addr()?);
    let tsa_url = format!("{origin}/tsa");
    let ocsp_url = format!("{origin}/ocsp");
    let crl_url = format!("{origin}/root.crl");
    let mut root = fixture_entry("user-rsa-sign");
    root.key = PrivateKey::from_pkcs8_der(
        include_bytes!("../../../../fixtures/openssl/rsa.pk8.der"),
        None,
    )?;
    root.cert = fixture_entry("root-gost2015.key").cert;
    let mut spec = TestCertSpec::from_cert(&fixture_entry("root-gost2015.key").cert);
    spec.subject = root.cert.tbs_certificate().subject().clone();
    spec.public_key = root.key.public_key().to_spki();
    spec.serial = vec![0x63, 0x33, 1];
    strip(&mut spec);
    root.cert = issue_cert(&root, spec);
    let mut doc = fixture_entry("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&doc.cert);
    strip(&mut spec);
    spec.serial = vec![0x63, 0x33, 2];
    status_extensions(&mut spec);
    doc.cert = issue_cert(&root, spec);
    doc = issue_local(doc, &root, &ocsp_url, &crl_url);
    let mut tsa = doc.clone();
    let mut spec = TestCertSpec::from_cert(&fixture_entry("tsa-gost2015").cert);
    strip(&mut spec);
    spec.public_key = tsa.key.public_key().to_spki();
    spec.serial = vec![0x63, 0x33, 3];
    status_extensions(&mut spec);
    tsa.cert = issue_cert(&root, spec);
    tsa = issue_local(tsa, &root, &ocsp_url, &crl_url);
    let mut responder = doc.clone();
    let mut spec = TestCertSpec::from_cert(&fixture_entry("ocsp-gost2015").cert);
    strip(&mut spec);
    spec.public_key = responder.key.public_key().to_spki();
    spec.serial = vec![0x63, 0x33, 4];
    responder.cert = issue_cert(&root, spec);
    let tsa_http = Arc::new(MockTsa::new(tsa.clone()).with_gen_time(FIXED_NOW));
    let ocsp_http = oncl_pki::ocsp::MockOcsp::new(responder).with_now(FIXED_NOW);
    let crl_http = oncl_pki::crl::MockCrl::new(root.clone())
        .with_this_update(FIXED_NOW - time::Duration::MINUTE)
        .next_update(Some(FIXED_NOW + time::Duration::HOUR));
    let crl = crl_http.der();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let tsa_server = tsa_http.clone();
    let base = origin.clone();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        let start = std::time::Instant::now();
        while !stopped.load(Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(120)
        {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            if count.fetch_add(1, Ordering::SeqCst) >= 512 {
                return Err("C03 fixture request limit".into());
            }
            socket.set_nonblocking(false).map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            let mut buffer = [0; 4096];
            let end = loop {
                let n = socket.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 || data.len() + n > 65_536 {
                    return Err("C03 incomplete/oversized request".into());
                }
                data.extend_from_slice(&buffer[..n]);
                if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let head = std::str::from_utf8(&data[..end])
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
            if length > 65_536 - end {
                return Err("C03 oversized body".into());
            }
            while data.len() - end < length {
                let n = socket.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 || data.len() + n > 65_536 {
                    return Err("C03 short/oversized body".into());
                }
                data.extend_from_slice(&buffer[..n]);
            }
            let mut first = head
                .lines()
                .next()
                .ok_or("missing method")?
                .split_whitespace();
            let method = first.next().ok_or("missing method")?;
            let path = first.next().ok_or("missing path")?;
            let url = format!("{base}{path}");
            let request = match method {
                "POST" => HttpRequest::post(
                    &url,
                    content_type,
                    &data[end..end + length],
                    GetOptions::default(),
                ),
                "GET" => HttpRequest::get(&url, GetOptions::default()),
                _ => return Err("C03 unsupported method".into()),
            };
            let reply = if path == "/tsa" {
                tsa_server.send(&request)
            } else if path == "/root.crl" {
                crl_http.send(&request)
            } else if path.starts_with("/ocsp") {
                ocsp_http.send(&request)
            } else {
                return Err("C03 unsupported path".into());
            }
            .map_err(|e| e.to_string())?;
            write!(socket, "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.status, reply.content_type.as_deref().unwrap_or("application/octet-stream"), reply.body.len()).map_err(|e| e.to_string())?;
            socket.write_all(&reply.body).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let server = EvidenceProbeServer {
        stop,
        thread: Some(thread),
    };
    let transport = UreqTransport::with_proxy(ProxySetting::None);
    let network = NetworkPolicy::only_endpoints([origin.as_str()])?;
    let budget = Arc::new(SharedBudget::new(ResourceLimits::default())?);
    let scope = || budget.begin(ResourceLimits::default(), Arc::new(Control));
    let ocsp_response = {
        let resources = scope()?;
        let http =
            oncl_pki::http::deadline::DeadlineTransport::new(&transport, &network, &resources);
        let request = oncl_pki::ocsp::request_der(&doc.cert, &root.cert);
        let response = http.send(&HttpRequest::post(
            &ocsp_url,
            Some("application/ocsp-request"),
            &request,
            GetOptions::default(),
        ))?;
        let fetched_crl = http.send(&HttpRequest::get(&crl_url, GetOptions::default()))?;
        http.finish()?;
        if response.status != 200 || fetched_crl.body != crl {
            return Err("C03 loopback public evidence fetch failed".into());
        }
        response.body
    };
    let ocsp_values = [ocsp_response.as_slice()];
    let anchors = CaSet::new(vec![root.cert.clone()]);
    let context = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: FIXED_NOW,
        anchors: &anchors,
        intermediates: &[],
        http: &transport,
    };
    let mut profile = TsaProfile::kalkan_default();
    profile.url = tsa_url;
    profile.method = TsaMethod::Post;
    let mut tsa_spec = TsaSpec::from(profile);
    tsa_spec.check_skew = None;
    let limits = EvidenceLimits {
        max_items: 128,
        max_bytes: 16 << 20,
        max_item_bytes: 2 << 20,
        max_crl_bytes: 16 << 20,
        max_crl_item_bytes: 2 << 20,
        max_total_bytes: 16 << 20,
        max_chain_len: 8,
        max_proofs: 16,
        max_coverage_parts: 4096,
        max_coverage_bytes: 10_737_418_240,
    };
    let certs: [Certificate; 2] = [root.cert.clone(), tsa.cert.clone()];
    let crls = [crl.as_slice()];
    let services = AdesServices {
        validation: &context,
        network: &network,
        temporary: &store,
        limits,
        tsa: Some(&tsa_spec),
        material: ValidationMaterial {
            certificates: &certs,
            ocsp: &ocsp_values,
            crls: &crls,
        },
        host_clock: None,
    };
    let document = b"C03 public RSA baseline document, genuinely timestamped over loopback.\n";
    std::fs::write(out.join("document.bin"), document)?;
    std::fs::write(out.join("root.der"), root.cert.to_der()?)?;
    std::fs::write(out.join("tsa.der"), tsa.cert.to_der()?)?;
    std::fs::write(out.join("signer.der"), doc.cert.to_der()?)?;
    std::fs::write(out.join("root.crl"), &crl)?;
    std::fs::write(out.join("signer-ocsp.der"), &ocsp_response)?;
    let mut summary = String::from(
        "case=C03\narchive_profile=EN319122-1 V1.3.1 archiveTimestampV3+ATSHashIndexV3 SHA-256\nprivate_material=none\n",
    );
    for attached in [true, false] {
        let label = if attached { "attached" } else { "detached" };
        let mut second = doc.clone();
        let mut spec = TestCertSpec::from_cert(&second.cert);
        spec.serial = vec![0x63, 0x33, 5];
        second.cert = issue_cert(&root, spec);
        let selectors = [selector(&doc)?, selector(&second)?];
        let guard = Arc::new(Consent {
            keys: selectors.iter().map(|key| key.key_id()).collect(),
            calls: AtomicUsize::new(0),
        });
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_keys(Arc::new(oncl_core::keys::KeySources::new()), guard.clone())
                .with_validation(oncl_core::ValidationServices::new(
                    CaSet::new(vec![root.cert.clone()]),
                    vec![],
                    Arc::new(UreqTransport::with_proxy(ProxySetting::None)),
                    network.clone(),
                    Arc::new(|| FIXED_NOW),
                ))
                .with_temporary_store(store.clone()),
        )?;
        let material = || ValidationMaterial {
            certificates: &certs,
            ocsp: &ocsp_values,
            crls: &crls,
        };
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Sign]).with_keys(selectors.iter().map(|key| key.key_id())),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )?;
        let mut current = Vec::new();
        engine.sign(
            oncl_core::SignRequest::cades_create(
                selectors
                    .iter()
                    .map(|key| oncl_core::keys::KeyRequest::new(key, Some("C03 synthetic")))
                    .collect(),
                attached,
                AdesLevel::B,
                material(),
                limits,
            ),
            Source::sequential(&mut Cursor::new(document), None),
            &mut current,
            &mut ctx,
        )?;
        for level in [AdesLevel::B, AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta] {
            if level != AdesLevel::B {
                let mut next = Vec::new();
                let mut detached = Cursor::new(document);
                let extend_engine = Engine::new(
                    EngineServices::hash_only(ResourceLimits::default())
                        .with_validation(oncl_core::ValidationServices::new(
                            CaSet::new(vec![root.cert.clone()]),
                            vec![],
                            Arc::new(UreqTransport::with_proxy(ProxySetting::None)),
                            network.clone(),
                            Arc::new(|| FIXED_NOW),
                        ))
                        .with_temporary_store(store.clone())
                        .with_cades(oncl_core::CadesConfiguration::new(limits, tsa_spec.clone())),
                )?;
                let mut ctx = extend_engine.begin(
                    ExecutionGrant::new([Action::Extend]),
                    OperationPolicy::strict_online(),
                    Arc::new(Control),
                )?;
                let request = oncl_core::ExtendRequest::cms(level)
                    .with_evidence_limits(limits)
                    .with_material(ValidationMaterial {
                        certificates: &certs,
                        ocsp: if level >= AdesLevel::Lt {
                            &ocsp_values
                        } else {
                            &[]
                        },
                        crls: if level >= AdesLevel::Lt { &crls } else { &[] },
                    });
                let request = if attached {
                    request
                } else {
                    request.with_detached(Source::sequential(&mut detached, None))
                };
                let extended = extend_engine.extend(
                    &request,
                    Source::sequential(&mut Cursor::new(&current), None),
                    &mut next,
                    &mut ctx,
                )?;
                if extended.applied != oncl_core::keys::AppliedState::NotApplied {
                    return Err("C03 public extension claimed key use".into());
                }
                current = next;
            }
            let mut detached = Cursor::new(document);
            let report = ades::verify(
                level,
                Source::sequential(&mut Cursor::new(&current), None),
                (!attached).then(|| Source::sequential(&mut detached, None)),
                &services,
                &[SigAlg::RsaSha256],
                &scope()?,
            )?;
            if report.verdict != Verdict::Valid
                || report.level() != Some(level)
                || report.reports().len() != 2
            {
                return Err(format!("C03 {label} {level:?} validation failed: {report:?}").into());
            }
            let stem = format!("rsa-{label}-{level:?}");
            std::fs::write(out.join(format!("{stem}.p7s")), &current)?;
            for (index, token) in tokens(&current)?.iter().enumerate() {
                std::fs::write(out.join(format!("{stem}-timestamp-{index}.der")), token)?;
            }
            summary.push_str(&format!(
                "{stem}=Valid signers=2 level={:?}\n",
                report.level()
            ));
        }
        let mut renewed = Vec::new();
        let mut detached = Cursor::new(document);
        let report = ades::extend(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&current), None),
            (!attached).then(|| Source::sequential(&mut detached, None)),
            &services,
            &[SigAlg::RsaSha256],
            &mut renewed,
            &scope()?,
        )?;
        if report.verdict != Verdict::Valid {
            return Err("C03 renewed archive failed".into());
        }
        drop(report);
        std::fs::write(out.join(format!("rsa-{label}-Renewed-Lta.p7s")), &renewed)?;
        current = renewed;
        summary.push_str(&format!(
            "rsa-{label}-renewal=Valid prior_proofs=retained\n"
        ));
        let mut third = doc.clone();
        let mut spec = TestCertSpec::from_cert(&third.cert);
        spec.serial = vec![0x63, 0x33, 6];
        third.cert = issue_cert(&root, spec);
        let third_selector = selector(&third)?;
        let add_guard = Arc::new(Consent {
            keys: vec![third_selector.key_id()],
            calls: AtomicUsize::new(0),
        });
        let add_engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_keys(
                    Arc::new(oncl_core::keys::KeySources::new()),
                    add_guard.clone(),
                )
                .with_validation(oncl_core::ValidationServices::new(
                    CaSet::new(vec![root.cert.clone()]),
                    vec![],
                    Arc::new(UreqTransport::with_proxy(ProxySetting::None)),
                    network.clone(),
                    Arc::new(|| FIXED_NOW),
                ))
                .with_temporary_store(store.clone()),
        )?;
        let mut ctx = add_engine.begin(
            ExecutionGrant::new([Action::Sign]).with_keys([third_selector.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )?;
        let mut added = Vec::new();
        let mut detached = Cursor::new(document);
        let report = add_engine.sign(
            oncl_core::SignRequest::cades_add(
                vec![oncl_core::keys::KeyRequest::new(
                    &third_selector,
                    Some("C03 synthetic"),
                )],
                (!attached).then(|| Source::sequential(&mut detached, None)),
                AdesLevel::B,
                material(),
                limits,
            ),
            Source::sequential(&mut Cursor::new(&current), None),
            &mut added,
            &mut ctx,
        )?;
        if report.applied != oncl_core::keys::AppliedState::Applied
            || add_guard.calls.load(Ordering::SeqCst) != 1
        {
            return Err("C03 Core Add key state incorrect".into());
        }
        let mut detached = Cursor::new(document);
        let report = ades::verify(
            AdesLevel::B,
            Source::sequential(&mut Cursor::new(&added), None),
            (!attached).then(|| Source::sequential(&mut detached, None)),
            &services,
            &[SigAlg::RsaSha256],
            &scope()?,
        )?;
        if report.verdict != Verdict::Valid
            || report.level() != Some(AdesLevel::B)
            || report.reports().len() != 3
        {
            return Err("C03 Core carried Add without issuance configuration failed".into());
        }
        drop(report);
        std::fs::write(out.join(format!("rsa-{label}-Add-B.p7s")), added)?;
        summary.push_str(&format!("rsa-{label}-Core-Add=Valid signers=3 minimum=B private=Applied issuance_configuration=absent\n"));
        let mut altered = current.clone();
        let at = altered.len() - 10;
        altered[at] ^= 1;
        let mut detached = Cursor::new(document);
        let report = ades::verify(
            AdesLevel::Lta,
            Source::sequential(&mut Cursor::new(&altered), None),
            (!attached).then(|| Source::sequential(&mut detached, None)),
            &services,
            &[SigAlg::RsaSha256],
            &scope()?,
        )?;
        if report.verdict != Verdict::Invalid {
            return Err("C03 altered archive accepted".into());
        }
        let before = add_guard.calls.load(Ordering::SeqCst);
        let mut detached = Cursor::new(document);
        let mut rejected_output = Vec::new();
        let error = add_engine
            .sign(
                oncl_core::SignRequest::cades_add(
                    vec![oncl_core::keys::KeyRequest::new(
                        &third_selector,
                        Some("C03 synthetic"),
                    )],
                    (!attached).then(|| Source::sequential(&mut detached, None)),
                    AdesLevel::B,
                    material(),
                    limits,
                ),
                Source::sequential(&mut Cursor::new(&altered), None),
                &mut rejected_output,
                &mut ctx,
            )
            .err()
            .ok_or("C03 Core Add accepted altered archive")?;
        if error.applied_state() != oncl_core::keys::AppliedState::NotApplied
            || add_guard.calls.load(Ordering::SeqCst) != before
            || !rejected_output.is_empty()
        {
            return Err("C03 invalid prior archive reached a new private guard/application".into());
        }
        std::fs::write(out.join(format!("rsa-{label}-Lta-altered.p7s")), altered)?;
        summary.push_str(&format!("rsa-{label}-altered=Invalid\n"));
        drop(report);
        if attached {
            let original = std::fs::read(out.join("rsa-attached-Lta.p7s"))?;
            let changed = changed_content_type(&original)?;
            let (ber, mixed) = {
                let resources = scope()?;
                let http = oncl_pki::http::deadline::DeadlineTransport::new(
                    &transport, &network, &resources,
                );
                let ber = reissue_archives(&changed, document, HashAlg::Sha256, &tsa_spec, &http)?;
                let mixed =
                    reissue_archives(&original, document, HashAlg::Sha512, &tsa_spec, &http)?;
                http.finish()?;
                (ber, mixed)
            };
            for (name, bytes, expected) in [
                ("review-raw-ber-Lta", &ber, Verdict::Valid),
                ("review-altered-content-type", &changed, Verdict::Invalid),
                ("review-mixed-imprint", &mixed, Verdict::Invalid),
            ] {
                let report = ades::verify(
                    AdesLevel::Lta,
                    Source::sequential(&mut Cursor::new(bytes), None),
                    None,
                    &services,
                    &[SigAlg::RsaSha256],
                    &scope()?,
                )?;
                if report.verdict != expected {
                    return Err(format!(
                        "C03 {name}: expected {expected:?}, got {:?}",
                        report.verdict
                    )
                    .into());
                }
                std::fs::write(out.join(format!("{name}.p7s")), bytes)?;
                summary.push_str(&format!("{name}={expected:?}\n"));
            }
            let before = add_guard.calls.load(Ordering::SeqCst);
            let mut rejected = Vec::new();
            let error = add_engine
                .sign(
                    oncl_core::SignRequest::cades_add(
                        vec![oncl_core::keys::KeyRequest::new(
                            &third_selector,
                            Some("C03 synthetic"),
                        )],
                        None,
                        AdesLevel::B,
                        material(),
                        limits,
                    ),
                    Source::sequential(&mut Cursor::new(&mixed), None),
                    &mut rejected,
                    &mut ctx,
                )
                .err()
                .ok_or("mixed archive reached Core Add")?;
            if error.applied_state() != oncl_core::keys::AppliedState::NotApplied
                || add_guard.calls.load(Ordering::SeqCst) != before
                || !rejected.is_empty()
            {
                return Err("mixed archive reached a new guard/private application".into());
            }
            let mut added = Vec::new();
            add_engine.sign(
                oncl_core::SignRequest::cades_add(
                    vec![oncl_core::keys::KeyRequest::new(
                        &third_selector,
                        Some("C03 synthetic"),
                    )],
                    None,
                    AdesLevel::B,
                    material(),
                    limits,
                ),
                Source::sequential(&mut Cursor::new(&ber), None),
                &mut added,
                &mut ctx,
            )?;
            std::fs::write(out.join("review-ber-Add-B.p7s"), added)?;
            let mut extended = Vec::new();
            let report = ades::extend(
                AdesLevel::Lta,
                Source::sequential(&mut Cursor::new(&ber), None),
                None,
                &services,
                &[SigAlg::RsaSha256],
                &mut extended,
                &scope()?,
            )?;
            if report.verdict != Verdict::Valid {
                return Err("raw BER extension failed".into());
            }
            std::fs::write(out.join("review-ber-extended-Lta.p7s"), extended)?;
            summary.push_str("review-mixed-Add=NotApplied new_guard_calls=0\nreview-ber-Add=Applied\nreview-ber-extend=Valid\n");
        }
    }
    server.finish()?;
    summary.push_str(&format!(
        "loopback_http_requests={}\n",
        calls.load(Ordering::SeqCst)
    ));
    std::fs::write(out.join("C03-report.txt"), &summary)?;
    println!("{summary}");
    Ok(())
}
