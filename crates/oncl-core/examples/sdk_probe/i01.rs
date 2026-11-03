//! Actual loopback HTTP TSA/status + file Source inspection and stamping.
use super::*;
#[path = "../../tests/support/i01.rs"]
mod fixture;
use der::Encode;
use oncl_core::{InspectRequest, StampRequest, StampVerifyRequest};
use oncl_pki::{
    http::{HttpRequest, HttpTransport, ProxySetting, UreqTransport},
    tsp::DocumentImprint,
    validation::Verdict,
};
use std::io::Write;
fn begin(
    engine: &Engine,
    action: Action,
) -> Result<oncl_core::OperationContext, oncl_core::OperationError> {
    engine.begin(
        ExecutionGrant::new([action]),
        OperationPolicy::strict_online(),
        Arc::new(Control),
    )
}
fn oracle(
    out: &std::path::Path,
    name: &str,
    data: &str,
    root: &str,
    valid: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = std::process::Command::new("openssl")
        .current_dir(out)
        .args([
            "ts",
            "-verify",
            "-token_in",
            "-in",
            "document.tst",
            "-data",
            data,
            "-CAfile",
            root,
            "-untrusted",
            "tsa.pem",
        ])
        .output()?;
    let mut log = format!("exit={:?}\nstdout:\n", result.status.code());
    log.push_str(&String::from_utf8_lossy(&result.stdout));
    log.push_str("\nstderr:\n");
    log.push_str(&String::from_utf8_lossy(&result.stderr));
    std::fs::write(out.join(name), log)?;
    if result.status.success() != valid {
        return Err(format!("independent OpenSSL control {name} had unexpected status").into());
    }
    Ok(())
}
pub(super) fn run(out: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("http://{}", listener.local_addr()?);
    let fixture = fixture::SignedFixtures::new(&origin, fixture::NOW, fixture::Status::Good);
    let server = fixture::Server::start(listener, fixture.clone());
    let transport = Arc::new(UreqTransport::with_proxy(ProxySetting::None));
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(fixture.services_with(true, transport.clone())),
    )?;
    let mut summary = String::from(
        "case=I01\nprofile=standalone RFC3161 SHA256/RSA synthetic trust only\nprivate_material_out=none\nlocal_private_key_use=none\nissuance_exactly_once=not_claimed\n",
    );
    let p12 = oncl_testkit::synthetic("multi-gost2015");
    {
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Inspect])
                .with_metadata_aliases(p12.aliases.iter().cloned()),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )?;
        let mut container = File::open(&p12.path)?;
        let length = container.metadata()?.len();
        let report = engine.inspect(
            &InspectRequest::container(Some(&p12.password)),
            Some(Source::sequential(&mut container, Some(length))),
            &mut ctx,
        )?;
        if report
            .entries()
            .iter()
            .map(|entry| entry.alias().unwrap())
            .collect::<Vec<_>>()
            != [
                "2174a152307df0e311ee3c01e07f7ecad448780c",
                "b8a0dd2f7728b2381484dd51a0ee85785b1f5343",
            ]
        {
            return Err("I01 exact alias mismatch".into());
        }
        for (index, entry) in report.entries().iter().enumerate() {
            summary.push_str(&format!(
                "alias={} fingerprint_sha256=",
                entry.alias().unwrap()
            ));
            for byte in entry.fingerprint().unwrap().as_bytes() {
                use std::fmt::Write;
                write!(summary, "{byte:02x}")?;
            }
            summary.push('\n');
            std::fs::write(
                out.join(format!("container-certificate-{index}.der")),
                entry
                    .certificate_der()
                    .ok_or("missing public certificate")?,
            )?;
        }
        summary.push_str(&format!(
            "container_intake={} container_output={}\n",
            report.bytes_in(),
            ctx.resources().progress().bytes_out
        ));
    }
    std::fs::write(out.join("root.der"), fixture.root.to_der()?)?;
    std::fs::write(
        out.join("root.pem"),
        oncl_pki::pem::encode("CERTIFICATE", &fixture.root.to_der()?),
    )?;
    std::fs::write(
        out.join("tsa.pem"),
        oncl_pki::pem::encode("CERTIFICATE", &fixture.tsa_cert.to_der()?),
    )?;
    std::fs::write(
        out.join("untrusted-root.pem"),
        oncl_pki::pem::encode(
            "CERTIFICATE",
            &oncl_testkit::read(oncl_testkit::fixture("synthetic/root-rsa.cer")),
        ),
    )?;
    std::fs::write(out.join("root.crl"), fixture.crl())?;
    {
        let mut ctx = begin(&engine, Action::Inspect)?;
        let mut input = File::open(out.join("root.der"))?;
        let report = engine.inspect(
            &InspectRequest::certificate(),
            Some(Source::seekable(&mut input, None)),
            &mut ctx,
        )?;
        summary.push_str(&format!(
            "certificate_subject={:?} certificate_signature_oid={}\n",
            report.entries()[0].subject_cn(),
            report.entries()[0].signature_algorithm_oid().unwrap()
        ));
    }
    let document = out.join("document.bin");
    {
        let mut file = File::create(&document)?;
        for index in 0..16384u32 {
            writeln!(
                file,
                "I01 real streaming file record {index:08}: immutable source data; only its digest reaches TSA."
            )?;
        }
    }
    {
        let mut ctx = begin(&engine, Action::Stamp)?;
        let mut input = File::open(&document)?;
        let mut output = File::create(out.join("document.tst"))?;
        let report = engine.stamp(
            &StampRequest::new(fixture.spec()),
            Source::seekable(&mut input, None),
            &mut output,
            &mut ctx,
        )?;
        if report.verdict() != Verdict::Valid {
            return Err("I01 stamp was not trusted".into());
        }
        summary.push_str(&format!("stamp_verdict={:?} stamp_input={} stamp_output={} signature={:?} eku={:?} chain={:?} revocation={:?} checked_at={} proven_time={}\n", report.verdict(), report.bytes_in(), report.bytes_out(), report.facts().signature(), report.facts().eku(), report.facts().chain(), report.facts().revocation(), report.facts().checked_at(), report.facts().gen_time()));
    }
    std::fs::copy(&document, out.join("changed.bin"))?;
    {
        use std::io::{Seek, SeekFrom};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(out.join("changed.bin"))?;
        file.seek(SeekFrom::Start(17))?;
        file.write_all(b"CHANGED")?;
    }
    for (name, data, expected) in [
        ("original", "document.bin", Verdict::Valid),
        ("changed", "changed.bin", Verdict::Invalid),
    ] {
        let mut ctx = begin(&engine, Action::VerifyStamp)?;
        let mut token = File::open(out.join("document.tst"))?;
        let mut data = File::open(out.join(data))?;
        let report = engine.verify_stamp(
            &StampVerifyRequest::new(),
            Source::seekable(&mut token, None),
            Some(Source::seekable(&mut data, None)),
            &mut ctx,
        )?;
        if report.verdict() != expected {
            return Err(format!("I01 {name} verification control failed").into());
        }
        summary.push_str(&format!(
            "{name}_verdict={:?} imprint={:?} bytes_in={} output={}\n",
            report.verdict(),
            report.facts().imprint(),
            report.bytes_in(),
            report.bytes_out()
        ));
    }
    {
        let mut ctx = begin(&engine, Action::VerifyStamp)?;
        let mut token = File::open(out.join("document.tst"))?;
        let report = engine.verify_stamp(
            &StampVerifyRequest::new(),
            Source::seekable(&mut token, None),
            None,
            &mut ctx,
        )?;
        if report.verdict() != Verdict::Indeterminate
            || report.facts().imprint() != DocumentImprint::NotProvided
        {
            return Err("I01 absent data was treated as a matched document".into());
        }
        summary.push_str("no_data=Indeterminate/NotProvided\n");
    }
    {
        let untrusted = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_validation(fixture.services_with(false, transport.clone())),
        )?;
        let mut ctx = begin(&untrusted, Action::VerifyStamp)?;
        let mut token = File::open(out.join("document.tst"))?;
        let mut data = File::open(&document)?;
        let report = untrusted.verify_stamp(
            &StampVerifyRequest::new(),
            Source::seekable(&mut token, None),
            Some(Source::seekable(&mut data, None)),
            &mut ctx,
        )?;
        if report.verdict() != Verdict::Invalid {
            return Err("I01 carried certificate became a trust root".into());
        }
        summary.push_str("untrusted_tsa=Invalid\n");
    }
    // Preserve actual public status bytes from the same pinned live transport.
    {
        let mut ctx = begin(&engine, Action::Validate)?;
        let network = oncl_pki::validation::NetworkPolicy::only_endpoints([&origin])?;
        let http = oncl_pki::http::deadline::DeadlineTransport::new(
            transport.as_ref(),
            &network,
            ctx.resources(),
        );
        let body = oncl_pki::ocsp::request_der(&fixture.tsa_cert, &fixture.root);
        let url = format!("{origin}/ocsp");
        let reply = http.send_scoped(&HttpRequest::post(
            &url,
            Some("application/ocsp-request"),
            &body,
            Default::default(),
        ))?;
        std::fs::write(out.join("tsa-ocsp.der"), reply.body())?;
        http.finish()?;
    }
    oracle(
        out,
        "openssl-original.txt",
        "document.bin",
        "root.pem",
        true,
    )?;
    oracle(out, "openssl-changed.txt", "changed.bin", "root.pem", false)?;
    oracle(
        out,
        "openssl-untrusted.txt",
        "document.bin",
        "untrusted-root.pem",
        false,
    )?;
    let requests = fixture.tsa.requests();
    summary.push_str(&format!(
        "tsa_requests={} http_requests={} request_document_bytes=not_sent\n",
        requests.len(),
        fixture.requests.load(std::sync::atomic::Ordering::SeqCst)
    ));
    for (index, request) in requests.iter().enumerate() {
        std::fs::write(out.join(format!("timestamp-request-{index}.der")), request)?;
    }
    std::fs::write(out.join("inspection-and-timestamp.txt"), &summary)?;
    server.finish()?;
    println!(
        "case=I01 aliases=exact public-inspection=verified stamp=Valid altered=Invalid untrusted=Invalid no-data=Indeterminate openssl=positive-and-negative http=loopback-pinned out={}",
        out.display()
    );
    Ok(())
}
