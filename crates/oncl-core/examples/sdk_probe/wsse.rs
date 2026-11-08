//! X05 actual protected >64-MiB SOAP, all three signing algorithms and loopback PKI.
//! Bounded external oracle inputs are separate; never DOM-parse the large source.
use super::{Control, fixture_entry, xml_sign_probe};
use der::Encode;
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy, SignRequest, ValidationServices, VerifyRequest,
    keys::{
        AppliedState, KeyLease, KeyProvider, KeyRequest, KeySelector, KeySources, KeyUseEvent,
        KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
    },
};
use oncl_pki::{
    http::{ProxySetting, UreqTransport},
    io::{Region, Source, TemporaryStore},
    key::HashAlg,
    pkix::CaSet,
    resource::ResourceLimits,
    validation::{CheckStatus, NetworkPolicy, Verdict},
};
use oncl_xml::wsse::{SourceWsseSignProfile, TokenReference, WsseVerifyProfile};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    net::TcpListener,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;
const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
const PREFIX: &str = "<?xml version='1.0'?>\r\n<env:Envelope xmlns:env='http://schemas.xmlsoap.org/soap/envelope/'><env:Header><m:note xmlns:m='urn:oncl:metadata'>uncovered-original</m:note></env:Header><env:Body><m:records xmlns:m='urn:oncl:measurements'><marker>covered-original</marker>";
const SUFFIX: &str = "</m:records></env:Body></env:Envelope>\r\n";
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
struct Guard {
    uses: AtomicUsize,
}
impl KeyUseGuard for Guard {
    fn before_use(
        &self,
        event: &KeyUseEvent,
    ) -> std::result::Result<KeyUseReceipt, OperationError> {
        if event.action != Action::Sign {
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
        if !outcome.succeeded || outcome.applied != AppliedState::Applied {
            return Err(OperationError::AuditFailed);
        }
        Ok(())
    }
}
fn check(value: bool, text: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(text).into())
    }
}
fn begin(engine: &Engine, action: Action, key: Option<&KeySelector>) -> Result<OperationContext> {
    let mut grant = ExecutionGrant::new([action]);
    if let Some(key) = key {
        grant = grant.with_keys([key.key_id()]);
    }
    Ok(engine.begin(grant, OperationPolicy::strict_online(), Arc::new(Control))?)
}
fn create(path: &Path) -> Result<(u64, u64)> {
    let mut writer = BufWriter::new(File::create(path)?);
    writer.write_all(PREFIX.as_bytes())?;
    let mut bytes = PREFIX.len() as u64;
    let mut records = 0;
    while bytes < 68 * 1024 * 1024 {
        let mut record = format!(
            "<record sequence='{records}' station='synthetic-{station}'><observed>2026-11-02T12:00:00Z</observed>",
            station = records % 997
        );
        for sample in 0..128 {
            use std::fmt::Write as _;
            write!(
                record,
                "<measurement sample='{sample}' unit='kPa' quality='calibrated'><value>{}.{:03}</value><description>Қысым өлшемі; pressure sample {} &amp; bounded synthetic telemetry</description></measurement>",
                records % 7000 + sample,
                (records * 17 + sample) % 1000,
                records * 128 + sample
            )?;
        }
        record.push_str("</record>");
        writer.write_all(record.as_bytes())?;
        bytes += record.len() as u64;
        records += 1;
    }
    writer.write_all(SUFFIX.as_bytes())?;
    writer.flush()?;
    bytes += SUFFIX.len() as u64;
    Ok((bytes, records))
}
fn sign(
    engine: &Engine,
    key: &KeySelector,
    input: &Path,
    output: &Path,
    store: &TemporaryStore,
    profile: SourceWsseSignProfile,
) -> Result<(Region, String)> {
    let mut ctx = begin(engine, Action::Sign, Some(key))?;
    let mut source = File::open(input)?;
    let len = source.metadata()?.len();
    let mut stage = store.stage(&mut ctx.resources().shared_view())?;
    let report = engine.sign_staged(
        SignRequest::wsse(KeyRequest::new(key, Some("X04 public synthetic")), profile),
        Source::seekable(&mut source, Some(len)),
        &mut stage,
        &mut ctx,
    )?;
    check(
        report.applied == AppliedState::Applied,
        "private use not Applied",
    )?;
    let xml = report.xml().ok_or("missing XML facts")?;
    check(
        xml.validation.verdict == Verdict::Valid,
        "signed SOAP not strictly Valid",
    )?;
    let facts = xml.facts.wsse().ok_or("missing actual Body binding")?;
    check(
        facts.signers().iter().all(|s| s.body_digest_matches()),
        "uncovered used Body",
    )?;
    let body = facts.used_body_region();
    let details = format!(
        "input={len} output={} used_body={body:?} signers={} actual_algorithms={:?} checked_at={} reference_facts={xml:#?}\n",
        report.bytes_out,
        report.signer_count(),
        xml.signatures()
            .iter()
            .map(|s| s.algorithm)
            .collect::<Vec<_>>(),
        xml.validation.checked_at
    );
    stage.copy_to(&mut File::create(output)?)?;
    Ok((body, details))
}
fn verify(engine: &Engine, path: &Path, expected: Verdict) -> Result<Region> {
    let mut ctx = begin(engine, Action::Verify, None)?;
    let mut source = File::open(path)?;
    let len = source.metadata()?.len();
    let report = engine.verify(
        &VerifyRequest::wsse(WsseVerifyProfile::default()),
        Source::seekable(&mut source, Some(len)),
        None,
        &mut ctx,
    )?;
    check(
        report.verdict == expected,
        &format!(
            "{}: expected {expected:?}, actual {:?}",
            path.display(),
            report.verdict
        ),
    )?;
    let facts = report
        .xml
        .as_ref()
        .and_then(|f| f.wsse())
        .ok_or("verification omitted SOAP coverage")?;
    if expected == Verdict::Valid {
        check(
            facts.signers().iter().all(|s| s.body_digest_matches()),
            "body coverage mismatch",
        )?;
        check(
            report
                .signers
                .iter()
                .all(|s| s.signature == CheckStatus::Passed),
            "signature math failure",
        )?;
    }
    Ok(facts.used_body_region())
}
fn mutate(
    input: &Path,
    output: &Path,
    marker: &[u8],
    replacement: &[u8],
    region: Region,
) -> Result<u64> {
    check(
        marker.len() == replacement.len(),
        "mutation must preserve offsets",
    )?;
    fs::copy(input, output)?;
    let mut file = fs::OpenOptions::new().read(true).write(true).open(output)?;
    check(
        region.end()? <= file.metadata()?.len(),
        "mutation region outside actual source",
    )?;
    file.seek(SeekFrom::Start(region.offset))?;
    let mut prefix = vec![0; region.len.min(65536) as usize];
    let n = file.read(&mut prefix)?;
    let at = prefix[..n]
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or("mutation marker absent from bounded prefix")?;
    let offset = region.offset + at as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(replacement)?;
    Ok(offset)
}
fn wrapped(input: &Path, output: &Path, body: Region) -> Result<()> {
    check(
        body.offset < 65536,
        "SOAP header exceeds bounded wrapping fixture prefix",
    )?;
    let mut source = File::open(input)?;
    let mut prefix = vec![0; body.offset as usize];
    source.read_exact(&mut prefix)?;
    let prefix = String::from_utf8(prefix)?;
    let prefix = prefix
        .strip_suffix("</env:Header>")
        .ok_or("actual direct Header boundary")?;
    let mut out = BufWriter::new(File::create(output)?);
    out.write_all(prefix.as_bytes())?;
    out.write_all(b"<m:wrapper xmlns:m='urn:oncl:attacker'>")?;
    source.seek(SeekFrom::Start(body.offset))?;
    io::copy(&mut Read::by_ref(&mut source).take(body.len), &mut out)?;
    out.write_all(b"</m:wrapper></env:Header><env:Body><forged/></env:Body></env:Envelope>")?;
    out.flush()?;
    Ok(())
}
pub fn run(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let origin = format!("http://{}", listener.local_addr()?);
    let (root, tsa, responder, rsa, gost15) = xml_sign_probe::pki(&origin)?;
    let mut gost04 = fixture_entry("user-gost2004-sign");
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&gost04.cert);
    xml_sign_probe::strip(&mut spec);
    spec.serial = vec![0x70, 5, 12];
    spec.extensions
        .push(xml_sign_probe::aia(&format!("{origin}/ocsp")));
    gost04.cert = oncl_pki::testing::issue_cert(&root, spec);
    fs::write(out.join("root.der"), root.cert.to_der()?)?;
    let server =
        xml_sign_probe::PkiServer::start(listener, origin.clone(), tsa, responder, out.to_owned())?;
    let provider = Arc::new(Provider {
        inner: KeySources::new(),
        opens: AtomicUsize::new(0),
    });
    let guard = Arc::new(Guard {
        uses: AtomicUsize::new(0),
    });
    let source = out.join("substantive-soap.xml");
    let (bytes, records) = create(&source)?;
    let limits = ResourceLimits {
        input_bytes: bytes,
        output_bytes: bytes + 1024 * 1024,
        container_bytes: 1024 * 1024,
        operation_timeout: std::time::Duration::from_secs(900),
        ..Default::default()
    };
    let store = TemporaryStore::new(out)?;
    let transport = UreqTransport::with_proxy(ProxySetting::None);
    let services = ValidationServices::new(
        CaSet::new(vec![root.cert.clone()]),
        vec![],
        Arc::new(transport),
        NetworkPolicy::only_endpoints([origin.as_str()])?,
        Arc::new(|| NOW),
    );
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_validation(services)
            .with_temporary_store(store.clone())
            .with_keys(provider.clone(), guard.clone()),
    )?;
    let rsa_key = xml_sign_probe::selector(&rsa)?;
    let gost15_key = xml_sign_probe::selector(&gost15)?;
    let gost04_key = xml_sign_probe::selector(&gost04)?;
    let big = out.join("substantive-rsa.xml");
    let (body, mut evidence) = sign(
        &engine,
        &rsa_key,
        &source,
        &big,
        &store,
        SourceWsseSignProfile::default(),
    )?;
    check(
        body.len > 64 * 1024 * 1024,
        "substantive covered Body must exceed 64 MiB",
    )?;
    verify(&engine, &big, Verdict::Valid)?;
    let added = out.join("substantive-rsa-gost15.xml");
    let (body, details) = sign(
        &engine,
        &gost15_key,
        &big,
        &added,
        &store,
        SourceWsseSignProfile {
            mode: oncl_xml::XmlSignMode::Add,
            ..Default::default()
        },
    )?;
    evidence.push_str(&details);
    fs::write(out.join("evidence.txt"), &evidence)?;
    verify(&engine, &added, Verdict::Valid)?;
    let covered = out.join("mutated-covered.xml");
    let changed_at = mutate(
        &added,
        &covered,
        b"covered-original",
        b"covered-attacker",
        body,
    )?;
    evidence.push_str(&format!(
        "covered_mutation_offset={changed_at} actual_body={body:?}\n"
    ));
    verify(&engine, &covered, Verdict::Invalid)?;
    let uncovered = out.join("mutated-uncovered.xml");
    mutate(
        &added,
        &uncovered,
        b"uncovered-original",
        b"uncovered-attacker",
        Region {
            offset: 0,
            len: body.offset,
        },
    )?;
    verify(&engine, &uncovered, Verdict::Valid)?;
    let wrapping = out.join("wrapped-old-body.xml");
    wrapped(&added, &wrapping, body)?;
    check(
        verify(&engine, &wrapping, Verdict::Valid).is_err(),
        "valid math on moved old Body accepted",
    )?;
    let wrong_ns = out.join("wrong-soap-namespace.xml");
    mutate(
        &added,
        &wrong_ns,
        b"http://schemas.xmlsoap.org/soap/envelope/",
        b"http://schemas.xmlsoap.org/soap/envelopE/",
        Region {
            offset: 0,
            len: body.offset,
        },
    )?;
    check(
        verify(&engine, &wrong_ns, Verdict::Valid).is_err(),
        "wrong actual Envelope namespace accepted",
    )?;
    let bounded = out.join("bounded-source.xml");
    fs::write(
        &bounded,
        format!(
            "{PREFIX}<record sequence='bounded'><measurement>42.125</measurement></record>{SUFFIX}"
        ),
    )?;
    for (name, key, token) in [
        ("rsa", &rsa_key, TokenReference::NcanodeX509KeyIdentifier),
        (
            "gost04",
            &gost04_key,
            TokenReference::NcanodeX509KeyIdentifier,
        ),
        (
            "gost15-bst",
            &gost15_key,
            TokenReference::BinarySecurityToken,
        ),
    ] {
        let (_, details) = sign(
            &engine,
            key,
            &bounded,
            &out.join(format!("bounded-{name}.xml")),
            &store,
            SourceWsseSignProfile {
                token_reference: token,
                ..Default::default()
            },
        )?;
        evidence.push_str(&details);
    }
    let opens = provider.opens.load(Ordering::SeqCst);
    let uses = guard.uses.load(Ordering::SeqCst);
    check(
        opens == 5 && uses == 5,
        "actual provider/private counts differ",
    )?;
    let calls = server.calls.load(Ordering::SeqCst);
    check(calls > 0, "no real loopback PKI request")?;
    let wire_digest = {
        let mut f = File::open(&added)?;
        let mut state = oncl_pki::digest::HashState::new(HashAlg::Sha256);
        let mut buf = vec![0; 256 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            state.update(&buf[..n]);
        }
        state.finish()
    };
    evidence.push_str(&format!("records={records} original_bytes={bytes} protected_body_bytes={} provider_opens={opens} private_uses={uses} loopback_pki_requests={calls} wire_sha256={wire_digest:?}\ncovered_mutation=Invalid uncovered_mutation=Valid wrapping=rejected namespace=rejected\nBounded RSA fixture for independent lxml/cryptography oracle; GOST-2004/2015 actual SDK cryptography+strict direct synthetic-root PKI, no independent GOST signature-math claim. No large DOM, production trust, measured RSS, 1-GiB or larger claim.\n", body.len));
    fs::write(out.join("evidence.txt"), &evidence)?;
    println!(
        "case=X05 original_bytes={bytes} records={records} covered_body_bytes={} provider_opens={opens} private_uses={uses} loopback_pki={calls} mutations=checked wrapping=rejected out={}",
        body.len,
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutation_uses_exact_body_region_not_header_substring() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source");
        let output = dir.path().join("changed");
        let source = b"<header>uncovered-original</header><body>covered-original</body>";
        fs::write(&input, source).unwrap();
        let offset = source.windows(6).position(|w| w == b"<body>").unwrap() as u64;
        let changed = mutate(
            &input,
            &output,
            b"covered-original",
            b"covered-attacker",
            Region {
                offset,
                len: source.len() as u64 - offset,
            },
        )
        .unwrap();
        assert!(changed >= offset);
        assert_eq!(
            fs::read(&output).unwrap(),
            b"<header>uncovered-original</header><body>covered-attacker</body>"
        );
    }
}
