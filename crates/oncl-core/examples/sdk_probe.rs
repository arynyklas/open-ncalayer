//! `printf abc | cargo run -p oncl-core --example sdk_probe -- hash --algorithm sha256 --input -`
use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
use oncl_pki::{io::Source, key::HashAlg};
use std::{fs::File, io, sync::Arc};

#[cfg(feature = "xml")]
#[path = "sdk_probe/xml.rs"]
mod xml_probe;

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    if command.as_deref() == Some("--case") {
        let case = args.next().ok_or("missing probe case")?;
        if !matches!(case.as_str(), "F04" | "C01" | "C02" | "X01") {
            return Err("unsupported probe case".into());
        }
        if args.next().as_deref() != Some("--out") {
            return Err("probe case requires --out <directory>".into());
        }
        let out = args.next().ok_or("missing probe output directory")?;
        if out.starts_with("--") {
            return Err("missing probe output directory".into());
        }
        if args.next().is_some() {
            return Err("unsupported or repeated probe argument".into());
        }
        return match case.as_str() {
            "C01" => cms_probe(std::path::Path::new(&out)),
            "C02" => cms_sign_probe(std::path::Path::new(&out)),
            "X01" => {
                #[cfg(feature = "xml")]
                {
                    xml_probe::run(std::path::Path::new(&out))?;
                    println!(
                        "case=X01 bounded-xml-crypto=verified rsa/gost2004/gost2015 tamper=rejected trust=not-evaluated out={out}"
                    );
                    Ok(())
                }
                #[cfg(not(feature = "xml"))]
                {
                    Err("X01 probe requires the xml feature".into())
                }
            }
            _ => evidence_probe(std::path::Path::new(&out)),
        };
    }
    if command.as_deref() == Some("keys") {
        if args.next().is_some() {
            return Err("keys probe takes no arguments and uses synthetic fixtures only".into());
        }
        return key_probe();
    }
    if command.as_deref() == Some("validation") {
        if args.next().is_some() {
            return Err("validation probe takes no arguments".into());
        }
        return validation_probe();
    }
    if command.as_deref() != Some("hash") {
        return Err(
            "usage: sdk_probe hash --algorithm <name> --input <path|-> | keys | validation | --case <F04|C01|C02|X01> --out <directory>".into(),
        );
    }
    let mut algorithm = None;
    let mut input = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--algorithm" if algorithm.is_none() => {
                algorithm = Some(match args.next().as_deref() {
                    Some("sha1") => HashAlg::Sha1,
                    Some("sha256") => HashAlg::Sha256,
                    Some("sha512") => HashAlg::Sha512,
                    Some("gost34311") => HashAlg::Gost34311,
                    Some("streebog256") => HashAlg::Streebog256,
                    Some("streebog512") => HashAlg::Streebog512,
                    _ => return Err("missing or unsupported hash algorithm".into()),
                });
            }
            "--input" if input.is_none() => {
                input = Some(args.next().ok_or("missing input path")?);
            }
            _ => return Err(format!("unsupported or repeated argument: {arg}").into()),
        }
    }
    let algorithm = algorithm.ok_or("--algorithm is required")?;
    let input = input.ok_or("--input is required")?;
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default()))?;
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Hash]),
        OperationPolicy::strict_online(),
        Arc::new(Control),
    )?;
    let report = if input == "-" {
        engine.hash(
            algorithm,
            Source::sequential(&mut io::stdin().lock(), None),
            &mut ctx,
        )?
    } else {
        let mut file = File::open(input)?;
        let len = file.metadata()?.len();
        engine.hash(algorithm, Source::seekable(&mut file, Some(len)), &mut ctx)?
    };
    use std::io::Write;
    let mut output = io::stdout().lock();
    write!(output, "digest=")?;
    for byte in report.digest.as_bytes() {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output, " bytes_in={}", report.bytes_in)?;
    Ok(())
}

/// Local host authority for this fixed synthetic probe, not a default server
/// audit backend and not consent for an arbitrary container/request.
struct ProbeGuard(Vec<oncl_core::keys::KeyId>);
impl oncl_core::keys::KeyUseGuard for ProbeGuard {
    fn before_use(
        &self,
        event: &oncl_core::keys::KeyUseEvent,
    ) -> Result<oncl_core::keys::KeyUseReceipt, oncl_core::OperationError> {
        if event.action != Action::SignDigest || !self.0.contains(&event.key_id) {
            return Err(oncl_core::OperationError::PermissionDenied);
        }
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
fn key_probe() -> Result<(), Box<dyn std::error::Error>> {
    use oncl_core::keys::{KeyRequest, KeySelector, KeySources};
    use oncl_pki::{digest::HashState, key::leaf_signature_algorithm};
    let names = ["user-gost2004-sign", "user-gost2015-sign", "user-rsa-sign"];
    let dir = tempfile::tempdir()?;
    let fixtures: Vec<_> = names
        .iter()
        .map(|name| probe_key_copy(name, dir.path()))
        .collect::<Result<_, _>>()?;
    let selectors: Vec<_> = fixtures
        .iter()
        .map(|fixture| KeySelector::file(&fixture.path, Some(fixture.aliases[0].clone())))
        .collect::<Result<_, _>>()?;
    let ids: Vec<_> = selectors.iter().map(KeySelector::key_id).collect();
    let services = EngineServices::hash_only(ResourceLimits::default());
    let provider = KeySources::new();
    #[cfg(feature = "tokens")]
    let (provider, token_selector) = {
        use oncl_token::{
            TokenKind, Tokens,
            emulator::{CardSpec, EmuKey, EmulatorBackend, card},
            execution::{TokenDeviceId, TokenGateRegistry},
        };
        let fixture = &fixtures[2];
        let emu = Arc::new(EmulatorBackend::new());
        emu.add_reader("F02 synthetic probe reader");
        emu.insert(
            "F02 synthetic probe reader",
            card(CardSpec::new(
                TokenKind::Kaztoken,
                "123456",
                vec![EmuKey::load(&fixture.path, &fixture.password)?],
            )),
        );
        let selector = KeySelector::token(
            TokenDeviceId::new("F02 synthetic probe reader")?,
            TokenKind::Kaztoken,
            fixture.aliases[0].clone(),
        );
        (
            provider.with_tokens(
                Tokens::new(emu, true),
                Arc::new(TokenGateRegistry::new(1, 1)?),
            ),
            selector,
        )
    };
    let guard_ids = ids.clone();
    #[cfg(feature = "tokens")]
    let guard_ids = {
        let mut ids = guard_ids;
        ids.push(token_selector.key_id());
        ids
    };
    let services = services
        .with_keys(Arc::new(provider), Arc::new(ProbeGuard(guard_ids.clone())))
        .with_validation(probe_validation());
    let engine = Engine::new(services)?;
    let mut policy = OperationPolicy::strict_online();
    policy.allow_prehashed = true;
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::SignDigest]).with_keys(guard_ids),
        policy,
        Arc::new(Control),
    )?;
    let message = b"F02 synthetic smoke: exactly one document hash";
    for ((fixture, selector), name) in fixtures.iter().zip(&selectors).zip(names) {
        let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)?
            .remove(0);
        let alg = leaf_signature_algorithm(entry.key.alg());
        let mut hash = HashState::new(alg.hash_alg());
        hash.update(message);
        let digest = hash.finish();
        let signature = engine
            .signer(
                &KeyRequest::new(selector, Some(&fixture.password)),
                &mut ctx,
            )?
            .sign_digest(&digest)?;
        entry.key.public_key().verify(alg, message, &signature)?;
        entry
            .key
            .public_key()
            .verify_digest(alg, &digest, &signature)?;
        println!("software {name}: verified");
    }
    #[cfg(feature = "tokens")]
    {
        let mut hash = HashState::new(HashAlg::Sha256);
        hash.update(message);
        let digest = hash.finish();
        let signature = engine
            .signer(&KeyRequest::new(&token_selector, Some("123456")), &mut ctx)?
            .sign_digest(&digest)?;
        let fixture = &fixtures[2];
        let entry = oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)?
            .remove(0);
        entry.key.public_key().verify_digest(
            oncl_pki::key::SigAlg::RsaSha256,
            &digest,
            &signature,
        )?;
        println!("token emulator: verified");
    }
    drop(ctx);
    let mut policy = OperationPolicy::strict_online();
    policy.allow_prehashed = true;
    let mut restricted = engine.begin(
        ExecutionGrant::new([Action::SignDigest]).with_keys([ids[0].clone()]),
        policy,
        Arc::new(Control),
    )?;
    let error = engine
        .signer(
            &KeyRequest::new(&selectors[2], Some(&fixtures[2].password)),
            &mut restricted,
        )
        .err()
        .ok_or("foreign key unexpectedly opened")?;
    if error.code() != oncl_core::ErrorCode::PermissionDenied
        || error.applied_state() != oncl_core::keys::AppliedState::NotApplied
    {
        return Err("foreign-key refusal was not pre-use".into());
    }
    println!("key-B denied before use; no signature");
    Ok(())
}

const FIXED_NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
fn fixture_entry(name: &str) -> oncl_pki::pkcs12::KeyEntry {
    let f = oncl_testkit::synthetic(name);
    oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn root_set() -> oncl_pki::pkix::CaSet {
    oncl_pki::pkix::CaSet::new(vec![
        oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-gost2015")).unwrap(),
    ])
}
fn probe_validation() -> oncl_core::ValidationServices {
    use oncl_pki::{
        crl::MockCrl,
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
    };
    let ocsp: Arc<dyn HttpTransport> =
        Arc::new(MockOcsp::new(fixture_entry("ocsp-gost2015")).with_now(FIXED_NOW));
    let crl: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(fixture_entry("root-gost2015.key"))
            .with_this_update(FIXED_NOW - time::Duration::MINUTE)
            .next_update(Some(FIXED_NOW + time::Duration::HOUR)),
    );
    oncl_core::ValidationServices::new(
        root_set(),
        vec![fixture_entry("inter-gost2015.key").cert],
        Arc::new(RouteTransport::new(vec![
            ("http://ocsp.synthetic.test".into(), ocsp),
            ("http://crl.synthetic.test".into(), crl),
        ])),
        oncl_pki::validation::NetworkPolicy::only_endpoints([
            "http://ocsp.synthetic.test",
            "http://crl.synthetic.test",
        ])
        .unwrap(),
        Arc::new(|| FIXED_NOW),
    )
}
fn probe_key_copy(
    name: &str,
    dir: &std::path::Path,
) -> Result<oncl_testkit::SyntheticKey, Box<dyn std::error::Error>> {
    use der::Encode;
    let mut fixture = oncl_testkit::synthetic(name);
    let mut key = fixture_entry(name);
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&key.cert);
    let source =
        oncl_pki::testing::TestCertSpec::from_cert(&fixture_entry("inter-user-gost2015-sign").cert);
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions
        .extend(source.extensions.into_iter().filter(|e| {
            matches!(
                e.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        }));
    key.cert = oncl_pki::testing::issue_cert(&fixture_entry("inter-gost2015.key"), spec);
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: key.alias,
            pkcs8_der: key.key.to_pkcs8_der()?.to_vec(),
            cert_der: Some(key.cert.to_der()?),
        }],
        &[],
        &fixture.password,
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x63),
    )?;
    fixture.path = dir.join(format!("{name}.p12"));
    std::fs::write(&fixture.path, bytes)?;
    Ok(fixture)
}
fn replace_uris(input: &[u8], url: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode, Reader, SliceReader};
    let any = der::asn1::AnyRef::from_der(input).unwrap();
    let tag = input[0];
    let body = if tag == 0x86 {
        url.to_vec()
    } else if tag & 0x20 != 0 {
        let mut reader = SliceReader::new(any.value()).unwrap();
        let mut body = vec![];
        while !reader.is_finished() {
            let child = reader
                .decode::<der::asn1::AnyRef<'_>>()
                .unwrap()
                .to_der()
                .unwrap();
            body.extend(replace_uris(&child, url));
        }
        body
    } else {
        any.value().to_vec()
    };
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let len: Vec<_> = body
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | len.len() as u8);
        out.extend(len);
    }
    out.extend(body);
    out
}
fn issue_local(
    mut key: oncl_pki::pkcs12::KeyEntry,
    issuer: &oncl_pki::pkcs12::KeyEntry,
    ocsp: &str,
    crl: &str,
) -> oncl_pki::pkcs12::KeyEntry {
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&key.cert);
    for extension in &mut spec.extensions {
        let url = match extension.extn_id.to_string().as_str() {
            "1.3.6.1.5.5.7.1.1" => Some(ocsp),
            "2.5.29.31" => Some(crl),
            _ => None,
        };
        if let Some(url) = url {
            extension.extn_value = der::asn1::OctetString::new(replace_uris(
                extension.extn_value.as_bytes(),
                url.as_bytes(),
            ))
            .unwrap();
        }
    }
    key.cert = oncl_pki::testing::issue_cert(issuer, spec);
    key
}
fn validation_probe() -> Result<(), Box<dyn std::error::Error>> {
    use oncl_pki::{
        cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec},
        crl::MockCrl,
        http::{GetOptions, HttpRequest, HttpTransport, UreqTransport},
        ocsp::MockOcsp,
        validation::{NetworkPolicy, Verdict},
    };
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = format!("http://{}", listener.local_addr()?);
    let root = fixture_entry("root-gost2015.key");
    let intermediate = issue_local(
        fixture_entry("inter-gost2015.key"),
        &root,
        &format!("{origin}/ocsp"),
        &format!("{origin}/root.crl"),
    );
    let leaf = issue_local(
        fixture_entry("inter-user-gost2015-sign"),
        &intermediate,
        &format!("{origin}/ocsp"),
        &format!("{origin}/leaf.crl"),
    );
    let input = cms::sign_spec(
        &leaf,
        &[intermediate.cert.clone(), root.cert.clone()],
        &SignSpec {
            content: Content::Data(b"F03 bounded synthetic CMS online/offline"),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(FIXED_NOW),
            certificates: CertSpec::Chain,
        },
    )?;
    let responder = MockOcsp::new(fixture_entry("ocsp-gost2015")).with_now(FIXED_NOW);
    let crl = MockCrl::new(root)
        .with_this_update(FIXED_NOW - time::Duration::MINUTE)
        .next_update(Some(FIXED_NOW + time::Duration::HOUR));
    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let stopped = stop.clone();
    let count = calls.clone();
    let base = origin.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let start = std::time::Instant::now();
        while !stopped.load(Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(20)
        {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                Err(e) => return Err(e.to_string()),
            };
            socket.set_nonblocking(false).map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            let mut chunk = [0; 4096];
            let header_end = loop {
                let n = socket.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 || data.len() + n > 1 << 20 {
                    return Err("incomplete/oversized fixture request".into());
                }
                data.extend_from_slice(&chunk[..n]);
                if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
            };
            let head = String::from_utf8(data[..header_end].to_vec()).map_err(|e| e.to_string())?;
            let length: usize = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, len)| len.trim().parse())
                .transpose()
                .map_err(|_| "bad Content-Length")?
                .unwrap_or(0);
            while data.len() - header_end < length {
                let n = socket.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("short fixture body".into());
                }
                data.extend_from_slice(&chunk[..n]);
                if data.len() > 1 << 20 {
                    return Err("large fixture body".into());
                }
            }
            let first: Vec<_> = head
                .lines()
                .next()
                .ok_or("missing HTTP request")?
                .split_whitespace()
                .collect();
            let path = *first.get(1).ok_or("missing path")?;
            let url = format!("{base}{path}");
            let request = if first[0] == "POST" {
                HttpRequest::post(
                    &url,
                    Some("application/ocsp-request"),
                    &data[header_end..header_end + length],
                    GetOptions::default(),
                )
            } else {
                HttpRequest::get(&url, GetOptions::default())
            };
            let response = if path.starts_with("/root.crl") || path.starts_with("/leaf.crl") {
                crl.send(&request)
            } else {
                responder.send(&request)
            }
            .map_err(|e| e.to_string())?;
            count.fetch_add(1, Ordering::SeqCst);
            write!(socket, "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.status, response.content_type.as_deref().unwrap_or("application/octet-stream"), response.body.len()).map_err(|e| e.to_string())?;
            socket
                .write_all(&response.body)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default()).with_validation(
            oncl_core::ValidationServices::new(
                root_set(),
                vec![intermediate.cert],
                Arc::new(UreqTransport::default()),
                NetworkPolicy::only_endpoints([origin.as_str()])?,
                Arc::new(|| FIXED_NOW),
            ),
        ),
    )?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut online = engine.begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )?;
        let report = engine.validate_cms(&input, None, &mut online)?;
        println!(
            "online verdict={:?} policy={:?} checked_at={} signers={:?}",
            report.verdict, report.policy, report.checked_at, report.signers
        );
        if report.verdict != Verdict::Valid || calls.load(Ordering::SeqCst) < 2 {
            return Err("online CMS did not validate using actual local OCSP/CRL".into());
        }
        drop(report);
        drop(online);
        let before = calls.load(Ordering::SeqCst);
        let mut offline = engine.begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )?;
        let report = engine.validate_cms(&input, None, &mut offline)?;
        println!(
            "offline verdict={:?} policy={:?} checked_at={} signers={:?} requests={}",
            report.verdict,
            report.policy,
            report.checked_at,
            report.signers,
            calls.load(Ordering::SeqCst) - before
        );
        if report.verdict != Verdict::Indeterminate || calls.load(Ordering::SeqCst) != before {
            return Err("offline CMS fetched or claimed unavailable evidence valid".into());
        }
        Ok(())
    })();
    stop.store(true, Ordering::SeqCst);
    server.join().map_err(|_| "fixture server panicked")??;
    result
}

/// One bounded synthetic HTTP server, always joined even on a probe failure.
struct EvidenceProbeServer {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}
impl EvidenceProbeServer {
    fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.thread
            .take()
            .ok_or("fixture server already joined")?
            .join()
            .map_err(|_| "fixture server panicked")??;
        Ok(())
    }
}
impl Drop for EvidenceProbeServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn evidence_probe(out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use der::Encode;
    use oncl_pki::{
        digest::HashState,
        evidence::{
            AdesLevel, CoveragePart, EvidenceKind, EvidenceLimits, EvidenceOrigin, EvidenceStore,
            ProofKind, SignerEvidence, TimestampBinding, validate_evidence,
        },
        http::deadline::DeadlineTransport,
        http::{GetOptions, HttpRequest, HttpTransport, NonceSpec, ProxySetting, UreqTransport},
        io::TemporaryStore,
        key::SigAlg,
        ocsp::{self, MockOcsp},
        pkix::CaSet,
        resource::SharedBudget,
        tsp::{self, MockTsa, TsaMethod, TsaProfile, TsaSpec},
        validation::{CheckStatus, NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
    };
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const PROVEN: time::OffsetDateTime = time::macros::datetime!(2025-06-01 10:05 UTC);
    const DOCUMENT: &[u8] = b"F04 genuine signed synthetic local HTTP evidence";
    const CHANGED_DOCUMENT: &[u8] = b"F04 changed content with another genuine signature";

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let origin = format!("http://{}", listener.local_addr()?);
    let ocsp_url = format!("{origin}/ocsp");
    let tsa_url = format!("{origin}/tsa");
    let root_url = format!("{origin}/root.crl");
    let leaf_url = format!("{origin}/leaf.crl");
    let root = fixture_entry("root-gost2015.key");
    let intermediate = issue_local(
        fixture_entry("inter-gost2015.key"),
        &root,
        &ocsp_url,
        &root_url,
    );
    let leaf = issue_local(
        fixture_entry("inter-user-gost2015-sign"),
        &intermediate,
        &ocsp_url,
        &leaf_url,
    );
    let mut tsa = fixture_entry("tsa-gost2015");
    let mut tsa_spec = oncl_pki::testing::TestCertSpec::from_cert(&tsa.cert);
    tsa_spec.serial = vec![0x74, 0x04];
    tsa_spec.extensions.retain(|ext| {
        !matches!(
            ext.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    tsa_spec.extensions.extend(
        oncl_pki::testing::TestCertSpec::from_cert(&leaf.cert)
            .extensions
            .into_iter()
            .filter(|ext| {
                matches!(
                    ext.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    tsa.cert = oncl_pki::testing::issue_cert(&intermediate, tsa_spec);
    let mut responder = fixture_entry("ocsp-gost2015");
    responder.cert = oncl_pki::testing::issue_cert(
        &intermediate,
        oncl_pki::testing::TestCertSpec::from_cert(&responder.cert),
    );
    let tsa_http = Arc::new(MockTsa::new(tsa.clone()).with_gen_time(PROVEN));
    let ocsp_http = MockOcsp::new(responder).with_now(FIXED_NOW);
    let root_crl = oncl_pki::crl::MockCrl::new(root.clone())
        .with_this_update(FIXED_NOW - time::Duration::MINUTE)
        .next_update(Some(FIXED_NOW + time::Duration::HOUR));
    let leaf_crl = oncl_pki::crl::MockCrl::new(intermediate.clone())
        .with_this_update(FIXED_NOW - time::Duration::MINUTE)
        .next_update(Some(FIXED_NOW + time::Duration::HOUR));
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let tsa_server = tsa_http.clone();
    let base = origin.clone();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        let start = std::time::Instant::now();
        while !stopped.load(Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(30)
        {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            if count.fetch_add(1, Ordering::SeqCst) >= 16 {
                return Err("fixture request count exceeded".into());
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
                    return Err("incomplete/oversized fixture request".into());
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
                            return Err("duplicate fixture Content-Length".into());
                        }
                        length = Some(
                            value
                                .trim()
                                .parse::<usize>()
                                .map_err(|_| "invalid fixture length")?,
                        );
                    }
                    if key.eq_ignore_ascii_case("content-type") {
                        content_type = Some(value.trim());
                    }
                }
            }
            let length = length.unwrap_or(0);
            if length > 65_536 - end {
                return Err("fixture body exceeds cap".into());
            }
            while data.len() - end < length {
                let n = socket.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 || data.len() + n > 65_536 {
                    return Err("short/oversized fixture body".into());
                }
                data.extend_from_slice(&buffer[..n]);
            }
            let mut first = head
                .lines()
                .next()
                .ok_or("missing fixture method")?
                .split_whitespace();
            let method = first.next().ok_or("missing fixture method")?;
            let path = first.next().ok_or("missing fixture path")?;
            let url = format!("{base}{path}");
            let request = match method {
                "POST" => HttpRequest::post(
                    &url,
                    content_type,
                    &data[end..end + length],
                    GetOptions::default(),
                ),
                "GET" => HttpRequest::get(&url, GetOptions::default()),
                _ => return Err("unsupported fixture method".into()),
            };
            let reply = if path == "/tsa" {
                tsa_server.send(&request)
            } else if path == "/root.crl" {
                root_crl.send(&request)
            } else if path == "/leaf.crl" {
                leaf_crl.send(&request)
            } else if path.starts_with("/ocsp") {
                ocsp_http.send(&request)
            } else {
                return Err("unsupported fixture route".into());
            }
            .map_err(|e| e.to_string())?;
            write!(socket, "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status, reply.content_type.as_deref().unwrap_or("application/octet-stream"), reply.body.len())
                .map_err(|e| e.to_string())?;
            socket.write_all(&reply.body).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let server = EvidenceProbeServer {
        stop,
        thread: Some(thread),
    };
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone())?);
    let mut resources = budget.begin(limits, Arc::new(Control))?;
    let network = NetworkPolicy::only_endpoints([origin.as_str()])?;
    let transport = UreqTransport::with_proxy(ProxySetting::None);
    let anchors = CaSet::new(vec![root.cert.clone()]);
    let candidates = vec![intermediate.cert.clone()];
    let ctx = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: FIXED_NOW,
        anchors: &anchors,
        intermediates: &candidates,
        http: &transport,
    };
    // Public response buffers are bounded/charged even in this executable host.
    let _responses = resources.reserve_memory(4 * oncl_pki::http::MAX_RESPONSE_LEN)?;
    let scoped_http = DeadlineTransport::new(&transport, &network, &resources);
    let fetch = |request: HttpRequest<'_>| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let reply = scoped_http.send(&request);
        scoped_http.finish()?;
        let reply = reply?;
        if reply.status != 200 {
            return Err("synthetic status fetch failed".into());
        }
        Ok(reply.body)
    };
    let doc_request = ocsp::request_der(&leaf.cert, &intermediate.cert);
    let tsa_request = ocsp::request_der(&tsa.cert, &intermediate.cert);
    let doc_status = fetch(HttpRequest::post(
        &ocsp_url,
        Some("application/ocsp-request"),
        &doc_request,
        GetOptions::default(),
    ))?;
    let tsa_status = fetch(HttpRequest::post(
        &ocsp_url,
        Some("application/ocsp-request"),
        &tsa_request,
        GetOptions::default(),
    ))?;
    let ca_status = fetch(HttpRequest::get(&root_url, GetOptions::default()))?;
    let mut hash = HashState::new(HashAlg::Streebog512);
    hash.update(DOCUMENT);
    let signature = leaf.key.sign(SigAlg::Gost2015_512, DOCUMENT)?;
    let signer = SignerEvidence {
        certificate: &leaf.cert,
        algorithm: SigAlg::Gost2015_512,
        signed_digest: hash.finish(),
        signature: &signature,
        claimed_time: None,
    };
    std::fs::create_dir_all(out)?;
    let temporary = TemporaryStore::new(out)?;
    let mut evidence = EvidenceStore::new(
        temporary.clone(),
        EvidenceLimits {
            max_items: 32,
            max_bytes: 4 * 1024 * 1024,
            max_item_bytes: 1024 * 1024,
            max_chain_len: 8,
            max_proofs: 4,
            max_coverage_parts: 64,
            max_coverage_bytes: 10_737_418_240,
        },
        &mut resources,
    )?;
    let public = [
        ("root.der", EvidenceKind::Certificate, root.cert.to_der()?),
        (
            "intermediate.der",
            EvidenceKind::Certificate,
            intermediate.cert.to_der()?,
        ),
        ("tsa.der", EvidenceKind::Certificate, tsa.cert.to_der()?),
        ("document-ocsp.der", EvidenceKind::Ocsp, doc_status),
        ("tsa-ocsp.der", EvidenceKind::Ocsp, tsa_status),
        ("root-crl.der", EvidenceKind::Crl, ca_status),
    ];
    for (name, kind, bytes) in &public {
        let provenance = match kind {
            EvidenceKind::Certificate => EvidenceOrigin::Embedded { label: name },
            EvidenceKind::Ocsp => EvidenceOrigin::Fetched {
                url: &ocsp_url,
                obtained_at: FIXED_NOW,
            },
            _ => EvidenceOrigin::Fetched {
                url: &root_url,
                obtained_at: FIXED_NOW,
            },
        };
        evidence.collect(
            *kind,
            Source::sequential(&mut bytes.as_slice(), Some(bytes.len() as u64)),
            provenance,
        )?;
    }
    let mut profile = TsaProfile::kalkan_default();
    profile.url = tsa_url;
    profile.method = TsaMethod::Post;
    let mut spec = TsaSpec::from(profile);
    spec.nonce = NonceSpec::Value(vec![0x04, 0x04]);
    let parts = [CoveragePart::Signature];
    let token = evidence.request_timestamp(&signer, &parts, &spec, &ctx, &network)?;
    let mut bundle = evidence.finish();
    let bindings = [TimestampBinding {
        token,
        kind: ProofKind::Signature,
        coverage: &parts,
    }];
    let valid = validate_evidence(
        &signer,
        &mut bundle,
        &bindings,
        AdesLevel::Lt,
        &ctx,
        &network,
        &resources,
    )?;
    if valid.verdict != Verdict::Valid
        || valid.signers[0].proof_time.as_ref().map(|p| p.at()) != Some(PROVEN)
    {
        return Err("F04 correct real HTTP evidence did not prove time".into());
    }
    let mut changed_hash = HashState::new(HashAlg::Streebog512);
    changed_hash.update(CHANGED_DOCUMENT);
    let changed_signature = leaf.key.sign(SigAlg::Gost2015_512, CHANGED_DOCUMENT)?;
    let changed_signer = SignerEvidence {
        signed_digest: changed_hash.finish(),
        signature: &changed_signature,
        ..signer
    };
    let changed = validate_evidence(
        &changed_signer,
        &mut bundle,
        &bindings,
        AdesLevel::Lt,
        &ctx,
        &network,
        &resources,
    )?;
    if changed.verdict != Verdict::Invalid
        || changed.signers[0].signature != CheckStatus::Passed
        || changed.signers[0].timestamp != CheckStatus::Failed
        || changed.signers[0].proof_time.is_some()
    {
        return Err("F04 changed imprint was not independently rejected".into());
    }
    let mut token_der = Vec::new();
    bundle.copy_entry(token, &mut token_der)?;
    let info = tsp::verify_token(&token_der)?;
    let expected = HashAlg::Sha256.digest(&signature);
    if info.imprint != expected || calls.load(Ordering::SeqCst) < 4 {
        return Err("F04 did not use actual bounded local TSA/OCSP/CRL".into());
    }
    server.finish()?;
    let publish = |name: &str,
                   bytes: &[u8],
                   resources: &mut oncl_pki::resource::ResourceScope|
     -> Result<(), Box<dyn std::error::Error>> {
        let mut artifact = temporary.stage(resources)?;
        for chunk in bytes.chunks(oncl_pki::resource::IO_CHUNK_BYTES) {
            artifact.write_chunk(chunk)?;
        }
        artifact.commit(&out.join(name))?;
        Ok(())
    };
    for (name, _, bytes) in &public {
        publish(name, bytes, &mut resources)?;
    }
    for (name, bytes) in [
        ("document.bin", DOCUMENT),
        ("changed-document.bin", CHANGED_DOCUMENT),
        ("signature.bin", signature.as_slice()),
        ("changed-signature.bin", changed_signature.as_slice()),
        ("covered.bin", signature.as_slice()),
        ("expected-imprint.bin", expected.as_slice()),
        ("timestamp.der", token_der.as_slice()),
    ] {
        publish(name, bytes, &mut resources)?;
    }
    let requests = tsa_http.requests();
    if requests.len() != 1 {
        return Err("F04 expected exactly one TSA request".into());
    }
    publish("tsa-request.der", &requests[0], &mut resources)?;
    let result = format!(
        "case=F04\ncoverage=raw signature octets; internal proof mechanism, not format-level AdES\nhost_clock={FIXED_NOW}\nexpected_proven={PROVEN}\nhttp_requests={}\nvalid={valid:?}\nchanged_imprint={changed:?}\n",
        calls.load(Ordering::SeqCst)
    );
    publish("validation.txt", result.as_bytes(), &mut resources)?;
    println!(
        "case=F04 valid={:?} changed_imprint={:?} http_requests={} out={}",
        valid.verdict,
        changed.verdict,
        calls.load(Ordering::SeqCst),
        out.display()
    );
    Ok(())
}

/// Fixed-size genuine CMS smoke artifacts. Large-document/RSS acceptance is a
/// separate controlled harness; these are real verification/extraction cases.
fn cms_probe(out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use der::asn1::AnyRef;
    use der::{Decode, Encode, Reader, SliceReader};
    use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
    use oncl_pki::validation::{CheckStatus, Verdict};
    use std::io::Cursor;
    const DOCUMENT: &[u8] = b"streamed C01 meaningful synthetic CMS content";
    fn children(input: &[u8]) -> Vec<Vec<u8>> {
        let any = AnyRef::from_der(input).unwrap();
        let mut reader = SliceReader::new(any.value()).unwrap();
        let mut fields = Vec::new();
        while !reader.is_finished() {
            fields.push(reader.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
        }
        fields
    }
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if body.len() < 128 {
            output.push(body.len() as u8);
        } else {
            let length = body.len().to_be_bytes();
            let first = length.iter().position(|byte| *byte != 0).unwrap();
            output.push(0x80 | (length.len() - first) as u8);
            output.extend_from_slice(&length[first..]);
        }
        output.extend_from_slice(body);
        output
    }
    fn indefinite(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut output = vec![tag, 0x80];
        output.extend_from_slice(body);
        output.extend_from_slice(&[0, 0]);
        output
    }
    fn carried_crl(input: &[u8], crl: &[u8]) -> Vec<u8> {
        let ci = children(input);
        let mut fields = children(&children(&ci[1])[0]);
        fields.insert(fields.len() - 1, tlv(0xa1, crl));
        tlv(
            0x30,
            &[ci[0].clone(), tlv(0xa0, &tlv(0x30, &fields.concat()))].concat(),
        )
    }
    fn ber(input: &[u8]) -> Vec<u8> {
        let ci = children(input);
        let mut fields = children(&children(&ci[1])[0]);
        let encap = children(&fields[2]);
        let mut body = encap[0].clone();
        if let Some(explicit) = encap.get(1) {
            let octets = children(explicit);
            let content = AnyRef::from_der(&octets[0]).unwrap().value();
            let chunks: Vec<u8> = content.chunks(7).flat_map(|chunk| tlv(4, chunk)).collect();
            body.extend(indefinite(0xa0, &indefinite(0x24, &chunks)));
        }
        fields[2] = indefinite(0x30, &body);
        indefinite(
            0x30,
            &[
                ci[0].clone(),
                indefinite(0xa0, &indefinite(0x30, &fields.concat())),
            ]
            .concat(),
        )
    }
    let key = fixture_entry("user-gost2015-sign");
    let root = fixture_entry("root-gost2015.key");
    let crl = oncl_pki::crl::MockCrl::new(root)
        .with_this_update(FIXED_NOW - time::Duration::MINUTE)
        .next_update(Some(FIXED_NOW + time::Duration::HOUR))
        .der();
    let make = |attached| -> Result<Vec<u8>, cms::CmsError> {
        Ok(carried_crl(
            &cms::sign_spec(
                &key,
                &[],
                &SignSpec {
                    content: Content::Data(DOCUMENT),
                    encapsulate: attached,
                    cosign: CoSign::Never,
                    econtent_type: None,
                    digest: None,
                    attrs: AttrSpec::cades(time::macros::datetime!(2025-06-01 10:00 UTC)),
                    certificates: CertSpec::Signer,
                },
            )?,
            &crl,
        ))
    };
    let attached = make(true)?;
    let detached = make(false)?;
    let attached_ber = ber(&attached);
    let detached_ber = ber(&detached);
    let mut tampered = attached.clone();
    let offset = tampered
        .windows(DOCUMENT.len())
        .position(|window| window == DOCUMENT)
        .ok_or("C01 fixture content not found")?;
    tampered[offset] ^= 1;
    let tampered_ber = ber(&tampered);
    std::fs::create_dir_all(out)?;
    let temporary = oncl_pki::io::TemporaryStore::new(out)?;
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default()).with_validation(probe_validation()),
    )?;
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Verify, Action::Extract]),
        OperationPolicy::offline_report(),
        Arc::new(Control),
    )?;
    let publish = |name: &str,
                   bytes: &[u8],
                   ctx: &mut oncl_core::OperationContext|
     -> Result<(), Box<dyn std::error::Error>> {
        let mut artifact = temporary.stage(ctx.resources())?;
        for chunk in bytes.chunks(oncl_pki::resource::IO_CHUNK_BYTES) {
            artifact.write_chunk(chunk)?;
        }
        artifact.commit(&out.join(name))?;
        Ok(())
    };
    publish("document.bin", DOCUMENT, &mut ctx)?;
    let mut summary = format!(
        "case=C01\nhost_clock={FIXED_NOW}\nextraction=raw unverified content; no signature verdict\n"
    );
    for (name, input, is_detached) in [
        ("cms-der-attached.p7s", &attached, false),
        ("cms-ber-attached.p7s", &attached_ber, false),
        ("cms-der-detached.p7s", &detached, true),
        ("cms-ber-detached.p7s", &detached_ber, true),
    ] {
        publish(name, input, &mut ctx)?;
        let mut external = Cursor::new(DOCUMENT);
        let data = is_detached.then(|| Source::sequential(&mut external, None));
        let report = engine.verify(
            &oncl_core::VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(input), None),
            data,
            &mut ctx,
        )?;
        if report.verdict != Verdict::Valid
            || report.signers.len() != 1
            || report.signers[0].signature != CheckStatus::Passed
        {
            return Err(format!("C01 real CMS did not validate: {name}: {report:?}").into());
        }
        summary.push_str(&format!("{name}={report:?}\n"));
        if !is_detached {
            let mut extracted = Vec::new();
            let result = engine.extract(
                Source::seekable(&mut Cursor::new(input), Some(input.len() as u64)),
                &mut extracted,
                &mut ctx,
            )?;
            if extracted != DOCUMENT || result.bytes_written != DOCUMENT.len() as u64 {
                return Err("C01 extracted content mismatch".into());
            }
            publish(
                if name.contains("-der-") {
                    "extracted-der.bin"
                } else {
                    "extracted-ber.bin"
                },
                &extracted,
                &mut ctx,
            )?;
        }
    }
    for (name, input) in [
        ("tampered-der.p7s", &tampered),
        ("tampered-ber.p7s", &tampered_ber),
    ] {
        publish(name, input, &mut ctx)?;
        let report = engine.verify(
            &oncl_core::VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(input), None),
            None,
            &mut ctx,
        )?;
        if report.verdict != Verdict::Invalid || report.signers[0].signature != CheckStatus::Failed
        {
            return Err("C01 content tamper was not rejected".into());
        }
        summary.push_str(&format!("{name}={report:?}\n"));
    }
    let missing = engine.verify(
        &oncl_core::VerifyRequest::cms(),
        Source::sequential(&mut Cursor::new(&detached_ber), None),
        None,
        &mut ctx,
    )?;
    if missing.verdict == Verdict::Valid {
        return Err("C01 missing detached content became Valid".into());
    }
    summary.push_str(&format!("missing-detached={missing:?}\n"));
    publish("verification.txt", summary.as_bytes(), &mut ctx)?;
    println!(
        "case=C01 DER/BER attached/detached=Valid tamper=Invalid missing-detached={:?} extraction=exact-unverified out={}",
        missing.verdict,
        out.display()
    );
    Ok(())
}

/// C02 publishes only public synthetic documents/signatures/certificates/reports.
fn cms_sign_probe(out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use der::Encode;
    use oncl_core::{
        SignRequest,
        keys::{
            KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome,
            KeyUseReceipt,
        },
    };
    use oncl_pki::{cms, io::TemporaryStore, key::leaf_signature_algorithm};
    use std::{
        io::{Cursor, Read},
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct Consent {
        keys: Vec<oncl_core::keys::KeyId>,
        attempts: AtomicUsize,
    }
    impl KeyUseGuard for Consent {
        fn before_use(
            &self,
            event: &KeyUseEvent,
        ) -> Result<KeyUseReceipt, oncl_core::OperationError> {
            if event.action != Action::Sign || !self.keys.contains(&event.key_id) {
                return Err(oncl_core::OperationError::PermissionDenied);
            }
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Ok(KeyUseReceipt::new(event.clone()))
        }
        fn finish(
            &self,
            _: KeyUseReceipt,
            outcome: KeyUseOutcome,
        ) -> Result<(), oncl_core::OperationError> {
            if outcome.succeeded && outcome.applied != oncl_core::keys::AppliedState::Applied {
                return Err(oncl_core::OperationError::AuditFailed);
            }
            Ok(())
        }
    }
    std::fs::create_dir_all(out)?;
    let scratch = tempfile::tempdir()?;
    let names = ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"];
    let mut fixtures: Vec<_> = names
        .iter()
        .map(|name| probe_key_copy(name, scratch.path()))
        .collect::<Result<_, _>>()?;
    // A distinct real RSA certificate/SignerIdentifier makes the RSA Add artifact
    // independently checkable without requiring an OpenSSL GOST provider.
    let mut rsa_extra = fixtures[0].clone();
    let mut entry =
        oncl_pki::pkcs12::load(&std::fs::read(&rsa_extra.path)?, &rsa_extra.password)?.remove(0);
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&entry.cert);
    spec.serial = vec![0x62, 0x02];
    entry.cert = oncl_pki::testing::issue_cert(&fixture_entry("inter-gost2015.key"), spec);
    let rsa_extra_certificate = entry.cert.to_der()?;
    let bytes = oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: entry.alias,
            pkcs8_der: entry.key.to_pkcs8_der()?.to_vec(),
            cert_der: Some(rsa_extra_certificate.clone()),
        }],
        &[],
        &rsa_extra.password,
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x64),
    )?;
    rsa_extra.path = scratch.path().join("rsa-cosigner.p12");
    std::fs::write(&rsa_extra.path, bytes)?;
    fixtures.push(rsa_extra);
    let keys: Vec<_> = fixtures
        .iter()
        .map(|f| KeySelector::file(&f.path, Some(f.aliases[0].clone())))
        .collect::<Result<_, _>>()?;
    let guard = Arc::new(Consent {
        keys: keys.iter().map(KeySelector::key_id).collect(),
        attempts: AtomicUsize::new(0),
    });
    let store = TemporaryStore::new(out)?;
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(Arc::new(KeySources::new()), guard.clone())
            .with_validation(probe_validation())
            .with_temporary_store(store.clone()),
    )?;
    let document = b"C02 source-bound streaming signature: public synthetic acceptance document.\n"
        .repeat(257);
    let publish = |name: &str, bytes: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )?;
        let mut artifact = store.stage(ctx.resources())?;
        artifact.write_chunk(bytes)?;
        artifact.commit(&out.join(name))?;
        Ok(())
    };
    publish("source.bin", &document)?;
    publish("rsa-cosigner-certificate.der", &rsa_extra_certificate)?;
    let mut summary = format!(
        "case=C02\nhost_clock={FIXED_NOW}\nsource_bytes={}\nprivate_material=none\n",
        document.len()
    );
    for (index, name) in names.iter().enumerate() {
        let fixture = &fixtures[index];
        let key = &keys[index];
        let entry =
            oncl_pki::pkcs12::load(&std::fs::read(&fixture.path)?, &fixture.password)?.remove(0);
        let algorithm = leaf_signature_algorithm(entry.key.alg());
        publish(&format!("{name}-certificate.der"), &entry.cert.to_der()?)?;
        publish(
            &format!("{name}-public.der"),
            &entry
                .cert
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()?,
        )?;
        for attached in [true, false] {
            let label = if attached { "attached" } else { "detached" };
            let path = out.join(format!("{name}-{label}.p7s"));
            {
                let mut ctx = engine.begin(
                    ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
                    OperationPolicy::strict_online(),
                    Arc::new(Control),
                )?;
                let mut artifact = store.stage(ctx.resources())?;
                let report = engine.sign_staged(
                    SignRequest::cms_create(
                        vec![KeyRequest::new(key, Some(&fixture.password))],
                        attached,
                    ),
                    Source::sequential(&mut Cursor::new(&document), None),
                    &mut artifact,
                    &mut ctx,
                )?;
                summary.push_str(&format!("{name}-{label}={report:?}\n"));
                artifact.commit(&path)?;
            }
            let original = std::fs::read(&path)?;
            if cms::verify(&original, (!attached).then_some(document.as_slice()))?.len() != 1 {
                return Err("C02 created signer count mismatch".into());
            }
            let second = if index == 0 { 3 } else { 0 };
            let second_key = &keys[second];
            let second_fixture = &fixtures[second];
            let cosigned_path = out.join(format!("{name}-{label}-add.p7s"));
            {
                let mut ctx = engine.begin(
                    ExecutionGrant::new([Action::Sign]).with_keys([second_key.key_id()]),
                    OperationPolicy::strict_online(),
                    Arc::new(Control),
                )?;
                let mut artifact = store.stage(ctx.resources())?;
                let mut detached = Cursor::new(&document);
                let request = SignRequest::cms_add(
                    vec![KeyRequest::new(second_key, Some(&second_fixture.password))],
                    (!attached).then(|| Source::sequential(&mut detached, None)),
                );
                let report = engine.sign_staged(
                    request,
                    Source::sequential(&mut Cursor::new(&original), None),
                    &mut artifact,
                    &mut ctx,
                )?;
                summary.push_str(&format!("{name}-{label}-add={report:?}\n"));
                artifact.commit(&cosigned_path)?;
            }
            let cosigned = std::fs::read(&cosigned_path)?;
            if cms::verify(&cosigned, (!attached).then_some(document.as_slice()))?.len() != 2 {
                return Err("C02 Add signer count mismatch".into());
            }
            let mut tampered = original.clone();
            *tampered.last_mut().ok_or("empty CMS")? ^= 1;
            let before = guard.attempts.load(Ordering::SeqCst);
            let mut ctx = engine.begin(
                ExecutionGrant::new([Action::Sign]).with_keys([second_key.key_id()]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )?;
            let mut detached = Cursor::new(&document);
            let result = engine.sign(
                SignRequest::cms_add(
                    vec![KeyRequest::new(second_key, Some(&second_fixture.password))],
                    (!attached).then(|| Source::sequential(&mut detached, None)),
                ),
                Source::sequential(&mut Cursor::new(&tampered), None),
                &mut Vec::new(),
                &mut ctx,
            );
            let error = result.err().ok_or("C02 accepted corrupted old signature")?;
            if error.applied_state() != oncl_core::keys::AppliedState::NotApplied
                || guard.attempts.load(Ordering::SeqCst) != before
            {
                return Err("C02 bad Add applied a new key".into());
            }
            summary.push_str(&format!("{name}-{label}-negative={error}\n"));
        }
        let raw_path = out.join(format!("{name}-raw.sig"));
        {
            let mut ctx = engine.begin(
                ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )?;
            let mut artifact = store.stage(ctx.resources())?;
            let report = engine.sign_staged(
                SignRequest::raw_message(KeyRequest::new(key, Some(&fixture.password))),
                Source::sequential(&mut Cursor::new(&document), None),
                &mut artifact,
                &mut ctx,
            )?;
            summary.push_str(&format!("{name}-raw={report:?}\n"));
            artifact.commit(&raw_path)?;
        }
        let mut signature = Vec::new();
        File::open(&raw_path)?.read_to_end(&mut signature)?;
        entry
            .key
            .public_key()
            .verify(algorithm, &document, &signature)?;
        if entry
            .key
            .public_key()
            .verify(algorithm, b"wrong C02 source", &signature)
            .is_ok()
        {
            return Err("C02 raw accepted wrong source".into());
        }
    }
    summary.push_str("local_crypto=all created/Add/raw outputs verified; bad Add and wrong raw source rejected\nexternal_oracles=NOTRUN; run Linux OpenSSL on new RSA artifacts and NCANode on Kazakhstan profiles\n");
    publish("C02-report.txt", summary.as_bytes())?;
    println!("{summary}");
    Ok(())
}
