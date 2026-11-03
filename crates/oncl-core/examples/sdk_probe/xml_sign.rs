//! X04: actual guarded large Source sign/Add/LTA, keyless renewal, loopback PKI.
use super::{Control, fixture_entry};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::{
    Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use oncl_core::{
    Action, CadesConfiguration, Engine, EngineServices, ExecutionGrant, ExtendRequest,
    OperationContext, OperationError, OperationPolicy, SignRequest, ValidationServices,
    VerifyRequest,
    keys::{
        AppliedState, KeyId, KeyLease, KeyProvider, KeyRequest, KeySelector, KeySources,
        KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
    },
};
use oncl_pki::{
    cert,
    digest::HashState,
    evidence::{AdesLevel, EvidenceLimits},
    http::{GetOptions, HttpRequest, HttpTransport, PkiMethod, ProxySetting, UreqTransport},
    io::{Region, Source, TemporaryStore},
    key::{HashAlg, SigAlg},
    keygen::{self, KeySpec},
    ocsp::MockOcsp,
    pkcs12::{self, KeyEntry},
    pkix::CaSet,
    resource::{ResourceLimits, SharedBudget},
    testing::{TestCertSpec, issue_cert},
    tsp::{MockTsa, TsaProfile, TsaSpec},
    validation::{NetworkPolicy, Verdict},
};
use std::{
    error::Error,
    fmt::Write as _,
    fs::{self, File},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use x509_cert::ext::Extension;
type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;
const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XA: &str = "http://uri.etsi.org/01903/v1.3.2#";
const X4: &str = "http://uri.etsi.org/01903/v1.4.1#";
fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 24,
        max_bytes: 6291456,
        max_item_bytes: 262144,
        max_chain_len: 16,
        max_proofs: 8,
        max_coverage_parts: 256,
        max_coverage_bytes: 1 << 40,
    }
}
fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.to_owned()).into())
    }
}
fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}
fn short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut out = vec![tag, body.len() as u8];
    out.extend_from_slice(body);
    out
}
fn aia(url: &str) -> Extension {
    let mut access = vec![6, 8, 43, 6, 1, 5, 5, 7, 48, 1];
    access.extend(short_tlv(0x86, url.as_bytes()));
    Extension {
        extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
        critical: false,
        extn_value: OctetString::new(short_tlv(0x30, &short_tlv(0x30, &access)))
            .expect("public AIA DER"),
    }
}
fn pki(origin: &str) -> Result<(KeyEntry, KeyEntry, KeyEntry, KeyEntry, KeyEntry)> {
    // New ephemeral synthetic CA/TSA/responder keys. Only public certificates,
    // requests, signatures and status responses are persisted by this probe.
    let mut root = fixture_entry("user-rsa-sign");
    root.key = keygen::generate(KeySpec::RsaSha256(2048))?;
    let mut spec =
        TestCertSpec::from_cert(&cert::parse(&oncl_testkit::synthetic_cert("root-rsa"))?);
    strip(&mut spec);
    spec.public_key = root.key.public_key().to_spki();
    spec.serial = vec![0x70, 4, 1];
    root.cert = issue_cert(&root, spec.clone());
    root.cert = issue_cert(&root, spec);
    let mut tsa = fixture_entry("user-rsa-sign");
    tsa.key = keygen::generate(KeySpec::RsaSha256(2048))?;
    let mut spec = TestCertSpec::from_cert(&fixture_entry("tsa-gost2015").cert);
    strip(&mut spec);
    spec.public_key = tsa.key.public_key().to_spki();
    spec.serial = vec![0x70, 4, 2];
    spec.extensions.push(aia(&format!("{origin}/ocsp")));
    tsa.cert = issue_cert(&root, spec);
    let mut responder = fixture_entry("user-rsa-sign");
    responder.key = keygen::generate(KeySpec::RsaSha256(2048))?;
    let mut spec = TestCertSpec::from_cert(&fixture_entry("ocsp-gost2015").cert);
    strip(&mut spec);
    spec.public_key = responder.key.public_key().to_spki();
    spec.serial = vec![0x70, 4, 3];
    responder.cert = issue_cert(&root, spec);
    let mut rsa = fixture_entry("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&rsa.cert);
    strip(&mut spec);
    spec.serial = vec![0x70, 4, 10];
    spec.extensions.push(aia(&format!("{origin}/ocsp")));
    rsa.cert = issue_cert(&root, spec);
    let mut gost = fixture_entry("user-gost2015-sign");
    let mut spec = TestCertSpec::from_cert(&gost.cert);
    strip(&mut spec);
    spec.serial = vec![0x70, 4, 11];
    spec.extensions.push(aia(&format!("{origin}/ocsp")));
    gost.cert = issue_cert(&root, spec);
    Ok((root, tsa, responder, rsa, gost))
}
struct PkiServer {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
    calls: Arc<AtomicUsize>,
}
impl Drop for PkiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            join.join().expect("loopback PKI thread");
        }
    }
}
impl PkiServer {
    fn start(
        listener: TcpListener,
        origin: String,
        tsa: KeyEntry,
        responder: KeyEntry,
        out: PathBuf,
    ) -> Result<Self> {
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let stopping = stop.clone();
        let counted = calls.clone();
        let join = thread::spawn(move || {
            let tsa = MockTsa::new(tsa).with_gen_time(NOW);
            let responder = MockOcsp::new(responder).with_now(NOW);
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        serve(
                            &mut stream,
                            &origin,
                            &tsa,
                            &responder,
                            &out,
                            counted.fetch_add(1, Ordering::SeqCst),
                        )
                        .expect("real loopback PKI exchange");
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("loopback listener: {e}"),
                }
            }
        });
        Ok(Self {
            stop,
            join: Some(join),
            calls,
        })
    }
}
fn serve(
    stream: &mut TcpStream,
    origin: &str,
    tsa: &MockTsa,
    responder: &MockOcsp,
    out: &Path,
    index: usize,
) -> Result<()> {
    // Accepted WinSock sockets can inherit the listener's nonblocking mode.
    // Only accept is polled; each actual bounded HTTP exchange is blocking.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = Vec::new();
    let mut chunk = [0; 4096];
    let end = loop {
        let n = stream.read(&mut chunk)?;
        check(n != 0, "short HTTP request")?;
        request.extend_from_slice(&chunk[..n]);
        check(request.len() <= 1 << 20, "PKI request cap")?;
        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let headers = std::str::from_utf8(&request[..end])?;
    let first = headers.lines().next().ok_or("HTTP request line")?;
    let method = first
        .split_whitespace()
        .next()
        .ok_or("HTTP method")?
        .to_owned();
    let path = first
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP request path")?
        .to_owned();
    let length = headers
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
                .map(|(_, v)| v.trim().parse::<usize>())
        })
        .transpose()?
        .unwrap_or(0);
    check(length <= 1 << 20, "PKI body cap")?;
    while request.len() < end + length {
        let n = stream.read(&mut chunk)?;
        check(n != 0, "short PKI body")?;
        request.extend_from_slice(&chunk[..n]);
        check(request.len() <= end + length, "unexpected HTTP pipelining")?;
    }
    let body = &request[end..end + length];
    let path = path.strip_prefix(origin).unwrap_or(&path);
    let url = format!("{origin}{path}");
    let is_tsa = path == "/tsa";
    check(
        is_tsa || path == "/ocsp" || path.starts_with("/ocsp/"),
        &format!("unexpected PKI endpoint: {method} {path}"),
    )?;
    let reply = if is_tsa {
        check(method == "POST", "timestamp binding must be POST")?;
        tsa.send(&HttpRequest::post(
            &url,
            Some("application/timestamp-query"),
            body,
            GetOptions::default(),
        ))?
    } else if method == "GET" {
        responder.send(&HttpRequest::get(&url, GetOptions::default()))?
    } else {
        check(method == "POST", "unsupported OCSP binding")?;
        responder.send(&HttpRequest::post(
            &url,
            Some("application/ocsp-request"),
            body,
            GetOptions::default(),
        ))?
    };
    if is_tsa {
        fs::write(out.join(format!("pki-{index:04}-tsa-request.der")), body)?;
        fs::write(
            out.join(format!("pki-{index:04}-tsa-response.der")),
            &reply.body,
        )?;
    }
    write!(
        stream,
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream"),
        reply.body.len()
    )?;
    stream.write_all(&reply.body)?;
    Ok(())
}
struct Consent {
    keys: Vec<KeyId>,
    uses: AtomicUsize,
}
impl KeyUseGuard for Consent {
    fn before_use(
        &self,
        event: &KeyUseEvent,
    ) -> std::result::Result<KeyUseReceipt, OperationError> {
        if event.action != Action::Sign || !self.keys.contains(&event.key_id) {
            return Err(OperationError::PermissionDenied);
        }
        self.uses.fetch_add(1, Ordering::SeqCst);
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(
        &self,
        _: KeyUseReceipt,
        outcome: KeyUseOutcome,
    ) -> std::result::Result<(), OperationError> {
        if outcome.succeeded && outcome.applied != AppliedState::Applied {
            return Err(OperationError::AuditFailed);
        }
        Ok(())
    }
}
struct Provider {
    inner: KeySources,
    opens: AtomicUsize,
}
impl KeyProvider for Provider {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> std::result::Result<KeyLease, OperationError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.inner.open(request, ctx)
    }
}
fn selector(entry: &KeyEntry) -> Result<KeySelector> {
    Ok(KeySelector::inline(
        pkcs12::write(
            &[pkcs12::WriteEntry {
                alias: entry.alias.clone(),
                pkcs8_der: entry.key.to_pkcs8_der()?.to_vec(),
                cert_der: Some(entry.cert.to_der()?),
            }],
            &[],
            "X04 public synthetic",
            &pkcs12::WriteOptions::default(),
            &mut |bytes| bytes.fill(0x74),
        )?,
        None,
    ))
}
fn begin(engine: &Engine, action: Action, key: Option<&KeySelector>) -> Result<OperationContext> {
    let grant = ExecutionGrant::new([action]);
    let grant = if let Some(key) = key {
        grant.with_keys([key.key_id()])
    } else {
        grant
    };
    Ok(engine.begin(grant, OperationPolicy::strict_online(), Arc::new(Control))?)
}
#[allow(
    clippy::too_many_arguments,
    reason = "Probe explicitly identifies its synthetic key, substantive input/output, level and shared store"
)]
fn sign(
    engine: &Engine,
    key: &KeySelector,
    input: &Path,
    output: &Path,
    id: &str,
    level: AdesLevel,
    add: bool,
    store: &TemporaryStore,
) -> Result<String> {
    let mut ctx = begin(engine, Action::Sign, Some(key))?;
    let mut file = File::open(input)?;
    let len = file.metadata()?.len();
    let mut stage = store.stage(&mut ctx.resources().shared_view())?;
    let profile = oncl_xml::XmlSignProfile {
        target: Some("payload"),
        parent: Some("signatures"),
        signature_id: Some(id),
        mode: if add {
            oncl_xml::XmlSignMode::Add
        } else {
            oncl_xml::XmlSignMode::Create
        },
        ..Default::default()
    };
    let report = engine.sign_staged(
        SignRequest::xades(
            KeyRequest::new(key, Some("X04 public synthetic")),
            profile,
            level,
        ),
        Source::seekable(&mut file, Some(len)),
        &mut stage,
        &mut ctx,
    )?;
    check(
        report.applied == AppliedState::Applied,
        "document key was not applied",
    )?;
    let xml = report.xml().ok_or("XML operation facts absent")?;
    check(
        xml.validation.verdict == Verdict::Valid,
        "actual signed output not Valid",
    )?;
    check(
        xml.signatures()
            .iter()
            .all(|s| s.references().iter().all(|r| r.digest_matches)),
        "actual reference mismatch",
    )?;
    check_prefix(
        input,
        &mut stage,
        xml.signatures()
            .last()
            .ok_or("new signature absent")?
            .signature
            .offset,
        ctx.resources(),
    )?;
    let details = format!(
        "input={} output={} bytes_in={} bytes_out={} applied={:?} signers={} minimum={:?} unsigned_prefix_exact=true\n{xml:#?}\n",
        input.display(),
        output.display(),
        report.bytes_in,
        report.bytes_out,
        report.applied,
        report.signer_count(),
        xml.minimum_level()
    );
    stage.copy_to(&mut File::create(output)?)?;
    Ok(details)
}
fn extend(
    engine: &Engine,
    input: &Path,
    output: &Path,
    level: AdesLevel,
    store: &TemporaryStore,
) -> Result<String> {
    let mut ctx = begin(engine, Action::Extend, None)?;
    let mut file = File::open(input)?;
    let len = file.metadata()?.len();
    let mut stage = store.stage(&mut ctx.resources().shared_view())?;
    let report = engine.extend_staged(
        &ExtendRequest::xml(level),
        Source::seekable(&mut file, Some(len)),
        &mut stage,
        &mut ctx,
    )?;
    check(
        report.applied == AppliedState::NotApplied,
        "extension used a private key",
    )?;
    let xml = report.xml().ok_or("extension XML facts absent")?;
    check(
        xml.validation.verdict == Verdict::Valid,
        "extension output invalid",
    )?;
    let details = format!(
        "extend={level:?} input={} output={} bytes_in={} bytes_out={} applied={:?}\n{xml:#?}\n",
        input.display(),
        output.display(),
        report.bytes_in,
        report.bytes_out,
        report.applied
    );
    stage.copy_to(&mut File::create(output)?)?;
    Ok(details)
}
fn verify(engine: &Engine, path: &Path, valid: bool) -> Result<String> {
    let mut ctx = begin(engine, Action::Verify, None)?;
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let report = engine.verify(
        &VerifyRequest::xml(),
        Source::seekable(&mut file, Some(len)),
        None,
        &mut ctx,
    )?;
    check(
        (report.verdict == Verdict::Valid) == valid,
        "mutation verdict differed from expected actual cryptographic result",
    )?;
    Ok(format!(
        "verify={} bytes={len} expected_valid={valid}\n{report:#?}\n",
        path.display()
    ))
}
fn region(path: &Path, region: Region) -> Result<Vec<u8>> {
    check(
        region.len <= 1 << 20,
        "probe refuses large metadata buffering",
    )?;
    let mut input = File::open(path)?;
    input.seek(SeekFrom::Start(region.offset))?;
    let mut bytes = vec![0; region.len as usize];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn reference_digests(
    engine: &Engine,
    path: &Path,
    expected: &[(&str, SigAlg, Vec<u8>)],
) -> Result<()> {
    let mut ctx = begin(engine, Action::Verify, None)?;
    let mut input = File::open(path)?;
    let len = input.metadata()?.len();
    let report = engine.verify(
        &VerifyRequest::xml(),
        Source::seekable(&mut input, Some(len)),
        None,
        &mut ctx,
    )?;
    check(
        report.verdict == Verdict::Valid,
        "large output failed verification",
    )?;
    let facts = report.xml.as_ref().ok_or("source facts absent")?;
    check(
        facts.signatures().len() == expected.len(),
        "large signer count",
    )?;
    for (fact, (id, algorithm, expected)) in facts.signatures().iter().zip(expected) {
        check(
            fact.algorithm == *algorithm,
            "leaf algorithm followed issuer instead of key",
        )?;
        let bytes = region(path, fact.signed_info)?;
        let wrapped = format!("<w xmlns:ds=\"{DS}\">{}</w>", std::str::from_utf8(&bytes)?);
        let parsed = roxmltree::Document::parse(&wrapped)?;
        let reference = parsed
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(DS)
                    && n.tag_name().name() == "Reference"
                    && n.attribute("URI") == Some("#payload")
            })
            .ok_or("payload reference absent")?;
        let digest = reference
            .children()
            .find(|n| n.tag_name().name() == "DigestValue")
            .and_then(|n| n.text())
            .ok_or("reference digest absent")?;
        check(
            STANDARD.decode(digest)? == *expected,
            "actual large Reference digest differs from independently emitted canonical record literals",
        )?;
        check(
            fact.references()[0]
                .target
                .is_some_and(|r| r.len > 64 * 1024 * 1024),
            "large protected target was only transport padding",
        )?;
        println!(
            "actual-large-reference signer={id} algorithm={algorithm:?} target={:?}",
            fact.references()[0].target
        );
    }
    Ok(())
}
fn canonical_artifacts(
    path: &Path,
    out: &Path,
    budget: &Arc<SharedBudget>,
    store: &TemporaryStore,
) -> Result<()> {
    let mut scope = budget.begin(ResourceLimits::default(), Arc::new(Control))?;
    let mut file = File::open(path)?;
    let mut doc = oncl_xml::XmlDocument::index(
        Source::seekable(&mut file, None),
        &oncl_xml::XmlLimits::default(),
        store,
        &mut scope,
    )?;
    let base = "//ds:Signature[1]/ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties";
    let specs = [
        ("reference-payload", "//*[@Id='payload']".to_owned()),
        (
            "reference-properties",
            "//xades:SignedProperties".to_owned(),
        ),
        ("SignedInfo", "//ds:SignedInfo".to_owned()),
        ("SignatureValue", "//ds:SignatureValue".to_owned()),
        ("KeyInfo", "//ds:KeyInfo".to_owned()),
        (
            "SignatureTimeStamp",
            format!("{base}/xades:SignatureTimeStamp"),
        ),
        (
            "TimeStampValidationData",
            format!("{base}/xades141:TimeStampValidationData"),
        ),
        ("RevocationValues", format!("{base}/xades:RevocationValues")),
    ];
    let mut archive = File::create(out.join("sdk-archive-input.bin"))?;
    for (name, xpath) in specs {
        let node = if name == "reference-payload" {
            doc.lookup_id("payload")?
        } else {
            doc.select_xpath(
                &xpath,
                &[("ds", DS), ("xades", XA), ("xades141", X4)],
                &mut scope,
            )?
        }
        .ok_or("oracle canonical node absent")?;
        let mut bytes = Vec::new();
        doc.canonicalize(
            Some(&node),
            oncl_xml::C14n::Exclusive,
            oncl_xml::C14nProfile::Standard,
            &mut bytes,
            &mut scope,
        )?;
        fs::write(out.join(format!("sdk-{name}.c14n")), &bytes)?;
        archive.write_all(&bytes)?;
    }
    Ok(())
}
pub(super) fn run(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("http://{}", listener.local_addr()?);
    let (root, tsa, responder, rsa, gost) = pki(&origin)?;
    fs::write(out.join("trusted-root.der"), root.cert.to_der()?)?;
    fs::write(out.join("tsa-certificate.der"), tsa.cert.to_der()?)?;
    fs::write(out.join("ocsp-certificate.der"), responder.cert.to_der()?)?;
    let server = PkiServer::start(listener, origin.clone(), tsa, responder, out.to_path_buf())?;
    let network = NetworkPolicy::only_endpoints([origin.as_str()])?;
    let store = TemporaryStore::new(out)?;
    let cap = ResourceLimits::default();
    let shared = Arc::new(SharedBudget::new(cap.clone())?);
    let rsa_key = selector(&rsa)?;
    let gost_key = selector(&gost)?;
    let consent = Arc::new(Consent {
        keys: vec![rsa_key.key_id(), gost_key.key_id()],
        uses: AtomicUsize::new(0),
    });
    let provider = Arc::new(Provider {
        inner: KeySources::new(),
        opens: AtomicUsize::new(0),
    });
    let mut tsa_spec = TsaSpec::from(TsaProfile::kalkan_default());
    tsa_spec.url = format!("{origin}/tsa");
    tsa_spec.method = PkiMethod::Post { content_type: None };
    let validation = || {
        ValidationServices::new(
            CaSet::new(vec![root.cert.clone()]),
            vec![],
            Arc::new(UreqTransport::with_proxy(ProxySetting::None)),
            network.clone(),
            Arc::new(|| NOW),
        )
    };
    let engine = Engine::new(
        EngineServices::hash_only(cap.clone())
            .with_shared_budget(shared.clone())
            .with_validation(validation())
            .with_temporary_store(store.clone())
            .with_cades(CadesConfiguration::new(evidence_limits(), tsa_spec.clone()))
            .with_keys(provider.clone(), consent.clone()),
    )?;
    let keyless = Engine::new(
        EngineServices::hash_only(cap)
            .with_shared_budget(shared.clone())
            .with_validation(validation())
            .with_temporary_store(store.clone())
            .with_cades(CadesConfiguration::new(evidence_limits(), tsa_spec)),
    )?;
    let bounded = out.join("bounded-input.xml");
    fs::write(
        &bounded,
        "<?xml version='1.0'?>\r\n<r xmlns:ds='urn:collision' xmlns:unused='urn:unused' xml:lang='outer'><data Id='payload' a='&quot;'>Құжат &amp; XML<item sequence='1'>24</item></data><s Id='signatures' xml:lang='kk'/><plain>outside</plain></r>\n",
    )?;
    let mut summary = String::from(
        "case=X04\nprofile=release-optimized-runtime\nstandard=ETSI EN319132-1 V1.2.1 section5.5.2.2 non-distributed v1.4.1\n",
    );
    let b = out.join("bounded-B.xml");
    summary.push_str(&sign(
        &engine,
        &rsa_key,
        &bounded,
        &b,
        "sig-rsa",
        AdesLevel::B,
        false,
        &store,
    )?);
    let mut previous = b.clone();
    for (level, name) in [
        (AdesLevel::T, "bounded-T.xml"),
        (AdesLevel::Lt, "bounded-LT.xml"),
        (AdesLevel::Lta, "bounded-LTA.xml"),
        (AdesLevel::Lta, "bounded-renewed-LTA.xml"),
    ] {
        let next = out.join(name);
        summary.push_str(&extend(&keyless, &previous, &next, level, &store)?);
        previous = next;
    }
    canonical_artifacts(&out.join("bounded-LTA.xml"), out, &shared, &store)?;
    let original = fs::read_to_string(&b)?;
    let extra=original.replacen("<ds:Object>","<ds:Object Id=\"attachment\"><e:record xmlns:e=\"urn:extra\">public &amp; protected</e:record></ds:Object><ds:Object>",1);
    check(extra != original, "extra Object insertion failed")?;
    let extra_b = out.join("bounded-extra-object-B.xml");
    fs::write(&extra_b, extra)?;
    summary.push_str(&extend(
        &keyless,
        &extra_b,
        &out.join("bounded-extra-object-LTA.xml"),
        AdesLevel::Lta,
        &store,
    )?);
    let input = out.join("medium-input.xml");
    let mut file = BufWriter::with_capacity(262144, File::create(&input)?);
    let prefix = b"<?xml version='1.0'?>\n<root><data Id=\"payload\"><records>";
    file.write_all(prefix)?;
    let mut rsa_hash = HashState::new(HashAlg::Sha256);
    let mut gost_hash = HashState::new(HashAlg::Streebog512);
    rsa_hash.update(b"<data Id=\"payload\"><records>");
    gost_hash.update(b"<data Id=\"payload\"><records>");
    let mut record_bytes = 0u64;
    let mut count = 0u64;
    while record_bytes < 65 * 1024 * 1024 {
        let mut record = String::with_capacity(32768);
        write!(
            &mut record,
            "<record category=\"public\" sequence=\"{count}\"><values>"
        )?;
        for item in 0..256u64 {
            write!(
                &mut record,
                "Құжат {count}/{item}: amount={} units={} status=reviewed &amp; retained; ",
                count * 257 + item,
                (item + 1) * 13
            )?;
        }
        record.push_str("</values></record>");
        file.write_all(record.as_bytes())?;
        rsa_hash.update(record.as_bytes());
        gost_hash.update(record.as_bytes());
        record_bytes += record.len() as u64;
        count += 1;
    }
    file.write_all(b"</records></data><s Id=\"signatures\"/><plain>outside</plain></root>\n")?;
    file.flush()?;
    drop(file);
    rsa_hash.update(b"</records></data>");
    gost_hash.update(b"</records></data>");
    let rsa_digest = rsa_hash.finish().as_bytes().to_vec();
    let gost_digest = gost_hash.finish().as_bytes().to_vec();
    let signed = out.join("medium-RSA-LTA.xml");
    summary.push_str(&sign(
        &engine,
        &rsa_key,
        &input,
        &signed,
        "sig-rsa",
        AdesLevel::Lta,
        false,
        &store,
    )?);
    let added = out.join("medium-RSA-LTA-GOST-B.xml");
    summary.push_str(&sign(
        &engine,
        &gost_key,
        &signed,
        &added,
        "sig-gost",
        AdesLevel::B,
        true,
        &store,
    )?);
    reference_digests(
        &keyless,
        &added,
        &[
            ("rsa", SigAlg::RsaSha256, rsa_digest.clone()),
            ("gost", SigAlg::Gost2015_512, gost_digest.clone()),
        ],
    )?;
    let mutation = out.join("medium-content-mutated.xml");
    fs::copy(&added, &mutation)?;
    let mut file = fs::OpenOptions::new().write(true).open(&mutation)?;
    file.seek(SeekFrom::Start(
        prefix.len() as u64 + "<record category=\"".len() as u64,
    ))?;
    file.write_all(b"P")?;
    drop(file);
    summary.push_str(&verify(&keyless, &mutation, false)?);
    let evidence_mutation = out.join("medium-evidence-mutated.xml");
    fs::copy(&added, &evidence_mutation)?;
    {
        let mut ctx = begin(&keyless, Action::Verify, None)?;
        let mut file = File::open(&added)?;
        let report = keyless.verify(
            &VerifyRequest::xml(),
            Source::seekable(&mut file, None),
            None,
            &mut ctx,
        )?;
        let signature = report.xml.as_ref().ok_or("mutation facts")?.signatures()[0].signature;
        let bytes = region(&added, signature)?;
        let text = std::str::from_utf8(&bytes)?;
        let parsed = roxmltree::Document::parse(text)?;
        let value = parsed
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(XA)
                    && n.tag_name().name() == "EncapsulatedOCSPValue"
                    && !n
                        .ancestors()
                        .any(|a| a.is_element() && a.tag_name().name() == "TimeStampValidationData")
            })
            .and_then(|n| n.first_child())
            .ok_or("actual carried signer OCSP missing")?;
        let at = value.range().end - 8;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&evidence_mutation)?;
        file.seek(SeekFrom::Start(signature.offset + at as u64))?;
        let mut old = [0];
        file.read_exact(&mut old)?;
        file.seek(SeekFrom::Start(signature.offset + at as u64))?;
        file.write_all(if old[0] == b'A' { b"B" } else { b"A" })?;
    }
    summary.push_str(&verify(&keyless, &evidence_mutation, false)?);
    // Runtime guard counts exclude the synthetic CA/TSA/responder fixture issuer.
    check(
        consent.uses.load(Ordering::SeqCst) == 3,
        "unexpected document private-use count",
    )?;
    check(
        provider.opens.load(Ordering::SeqCst) == 3,
        "unexpected document key-open count",
    )?;
    writeln!(
        &mut summary,
        "record_count={count}\nactual_record_bytes={record_bytes}\nactual_input_bytes={}\nmanual_canonical_sha256={}\nmanual_canonical_gost512={}\ndocument_key_opens={}\ndocument_private_uses={}\nkeyless_extension_provider=absent\nloopback_pki_requests={}\nlarge_document_DOM=not-used\nindependent_oracle=run xml_xades_oracle.py --out DIR\n10GiB_RSS_gate=not-run\n",
        fs::metadata(&input)?.len(),
        STANDARD.encode(rsa_digest),
        STANDARD.encode(gost_digest),
        provider.opens.load(Ordering::SeqCst),
        consent.uses.load(Ordering::SeqCst),
        server.calls.load(Ordering::SeqCst)
    )?;
    fs::write(out.join("X04-runtime-report.txt"), &summary)?;
    println!("{summary}");
    Ok(())
}

fn check_prefix(
    path: &Path,
    stage: &mut oncl_pki::io::StagedArtifact,
    signature_offset: u64,
    scope: &oncl_pki::resource::ResourceScope,
) -> Result<()> {
    let mut original = File::open(path)?;
    let mut limit = signature_offset;
    if limit > 0 && limit - 1 < original.metadata()?.len() {
        original.seek(SeekFrom::Start(limit - 1))?;
        let mut marker = [0];
        original.read_exact(&mut marker)?;
        if marker[0] == b'/' {
            limit -= 1;
        }
    }
    original.seek(SeekFrom::Start(0))?;
    let _memory = scope.reserve_memory(2 * 262144)?;
    let mut buffers = vec![0; 2 * 262144];
    let (a, b) = buffers.split_at_mut(262144);
    let mut offset = 0;
    while offset < limit {
        let n = stage.read_region(
            Region {
                offset,
                len: limit - offset,
            },
            a,
        )?;
        check(n != 0, "signed prefix extent")?;
        original.read_exact(&mut b[..n])?;
        check(a[..n] == b[..n], "unsigned original lexical prefix changed")?;
        offset += n as u64;
    }
    Ok(())
}
