use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationPolicy, ValidationServices,
    VerifyRequest,
};
use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::Source,
    pkix::CaSet,
    resource::ResourceLimits,
    validation::{CheckStatus, NetworkPolicy, Verdict},
};
use std::{io::Cursor, path::Path, sync::Arc};
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        panic!("offline P01 attempted network")
    }
}
pub fn run(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    let cert = include_bytes!("../../../oncl-pdf/tests/fixtures/external-cert.der");
    let services = ValidationServices::new(
        CaSet::new(vec![oncl_pki::cert::parse(cert)?]),
        vec![],
        Arc::new(Offline),
        NetworkPolicy::deny_all(),
        Arc::new(|| time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap()),
    );
    let store = oncl_pki::io::TemporaryStore::new(out)?;
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(services)
            .with_temporary_store(store),
    )?;
    let mut summary = String::new();
    for (name, bytes, crypto, later) in [
        (
            "external-signed.pdf",
            include_bytes!("../../../oncl-pdf/tests/fixtures/external-signed.pdf").as_slice(),
            CheckStatus::Passed,
            false,
        ),
        (
            "external-mutated.pdf",
            include_bytes!("../../../oncl-pdf/tests/fixtures/external-mutated.pdf").as_slice(),
            CheckStatus::Failed,
            false,
        ),
        (
            "external-later.pdf",
            include_bytes!("../../../oncl-pdf/tests/fixtures/external-later.pdf").as_slice(),
            CheckStatus::Passed,
            true,
        ),
    ] {
        let mut ctx = engine.begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(super::Control),
        )?;
        let mut cursor = Cursor::new(bytes);
        let report = engine.verify(
            &VerifyRequest::pdf(),
            Source::seekable(&mut cursor, None),
            None,
            &mut ctx,
        )?;
        let facts = report.pdf.as_ref().ok_or("missing PDF facts")?;
        if report.signers.len() != 1
            || report.signers[0].signature != crypto
            || facts.signatures[0].later_changes != later
            || report.verdict == Verdict::Valid
        {
            return Err("P01 crypto/revision/trust negative control failed".into());
        }
        let line = format!(
            "file={name} verdict={:?} crypto={:?} revision={} protected_end={} ranges={:?} later_changes={} extent={}\n",
            report.verdict,
            report.signers[0].signature,
            facts.signatures[0].revision,
            facts.signatures[0].revision_end,
            facts.signatures[0].byte_range.values(),
            later,
            facts.extent
        );
        print!("{line}");
        summary.push_str(&line);
        std::fs::write(out.join(name), bytes)?;
    }
    std::fs::write(out.join("external-cert.der"), cert)?;
    std::fs::write(out.join("p01-results.txt"), summary)?;
    println!(
        "case=P01 external-pyhanko-rsa=verified inside-mutation=rejected outside-revision=reported trust=offline-indeterminate"
    );
    Ok(())
}
