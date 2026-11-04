use crate::{
    args::{Cli, evidence_limits},
    families::*,
    local::Input,
    output,
    reports::{self, DebugText},
    secrets,
};
use oncl_core::{Engine, OperationContext, OperationError};
use oncl_pki::{resource::ProcessingError, tsp::TsaSpec};
use std::time::Duration;

pub fn inspect(
    engine: &Engine,
    args: &InspectArgs,
    selector: Option<&oncl_core::keys::KeySelector>,
    cli: &Cli,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    let _secret_memory = ctx.resources().reserve_memory(16384)?;
    let secret = if matches!(
        args.profile,
        InspectProfile::Container | InspectProfile::NamedKey
    ) {
        Some(secrets::read(
            args.secret_file.as_deref(),
            args.secret_interactive,
            args.input.as_deref() == Some("-"),
            ctx,
        )?)
    } else {
        None
    };
    let named = selector.map(|selector| {
        oncl_core::keys::KeyRequest::new(selector, secret.as_deref().map(String::as_str))
    });
    let request = match args.profile {
        InspectProfile::NamedKey => oncl_core::InspectRequest::named_key(
            named.as_ref().ok_or(OperationError::InvalidKeySource)?,
        ),
        InspectProfile::Certificate => oncl_core::InspectRequest::certificate(),
        InspectProfile::Container => {
            oncl_core::InspectRequest::container(secret.as_deref().map(String::as_str))
        }
        InspectProfile::Cms => oncl_core::InspectRequest::cms_metadata(),
    };
    let mut input = args.input.as_deref().map(Input::open).transpose()?;
    let report = engine.inspect(&request, input.as_mut().map(Input::source), ctx)?;
    output::report(
        cli,
        &reports::Inspection(&report),
        "Completed (structural metadata; not validation)",
        ctx,
    )?;
    Ok(0)
}
pub fn extend(
    engine: &Engine,
    args: &ExtendArgs,
    cli: &Cli,
    evidence: &crate::evidence::Material,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    let mut source = Input::open(&args.input)?;
    let mut detached = args.detached.as_deref().map(Input::open).transpose()?;
    let request = match args.profile {
        ExtendProfile::Cms => oncl_core::ExtendRequest::cms(args.level.sdk()),
        ExtendProfile::Xml => oncl_core::ExtendRequest::xml(args.level.sdk()),
        ExtendProfile::Pdf => {
            oncl_core::ExtendRequest::pdf(args.level.sdk(), oncl_pdf::PdfLimits::default())
        }
    }
    .with_evidence_limits(evidence_limits());
    let (ocsp, crls) = (evidence.ocsp_slices(), evidence.crl_slices());
    let request = request.with_material(oncl_pki::cms::ades::ValidationMaterial {
        certificates: &evidence.certificates,
        ocsp: &ocsp,
        crls: &crls,
    });
    let request = if let Some(detached) = &mut detached {
        request.with_detached(detached.source())
    } else {
        request
    };
    let store = output::store(cli, &args.output)?;
    let mut stage = store.stage(ctx.resources())?;
    let report = engine.extend_staged(&request, source.source(), &mut stage, ctx)?;
    let prepared = output::prepare(
        cli,
        &reports::Written::from(&report),
        "Completed (public evidence extension)",
        true,
        ctx,
    )?;
    output::deliver(stage, &args.output)?;
    prepared.send()?;
    Ok(0)
}
/// Operator-requested TSA policy OID (dotted). XAdES evidence requires one.
pub fn policy(text: &str) -> Result<der::asn1::ObjectIdentifier, OperationError> {
    text.parse()
        .map_err(|_| ProcessingError::InvalidInput("invalid host TSA policy").into())
}
pub fn tsa(
    url: &str,
    algorithm: oncl_pki::key::HashAlg,
    timeout: Duration,
    policy_oid: Option<&str>,
) -> Result<TsaSpec, OperationError> {
    Ok(TsaSpec {
        url: url.to_owned(),
        method: oncl_pki::http::PkiMethod::Post { content_type: None },
        hash: algorithm,
        policy: policy_oid.map(policy).transpose()?,
        nonce: oncl_pki::http::NonceSpec::Random(16),
        cert_req: true,
        retries: 0,
        timeout,
        check_skew: Some(Duration::from_secs(300)),
        require_tsa_eku: true,
    })
}
pub fn timestamp(
    engine: &Engine,
    args: &TimestampCommand,
    cli: &Cli,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    #[derive(serde::Serialize)]
    struct Report<'a> {
        operation_id: u64,
        code: &'static str,
        applied: &'static str,
        verdict: &'static str,
        policy: DebugText<oncl_pki::validation::ValidationPolicy>,
        facts: DebugText<&'a oncl_pki::tsp::DocumentTimestamp>,
        bytes_in: u64,
        bytes_out: u64,
    }
    match args {
        TimestampCommand::Acquire {
            input,
            output: destination,
            tsa: url,
            algorithm,
        } => {
            let request = oncl_core::StampRequest::new(tsa(
                url,
                algorithm.sdk(),
                Duration::from_secs(cli.timeout_seconds),
                cli.tsa_policy.as_deref(),
            )?);
            let mut source = Input::open(input)?;
            let store = output::store(cli, destination)?;
            let mut stage = store.stage(ctx.resources())?;
            let result = engine.stamp_staged(&request, source.source(), &mut stage, ctx)?;
            let report = Report {
                operation_id: result.id().get(),
                code: "Completed",
                applied: "NotApplied",
                verdict: reports::verdict(result.verdict()).0,
                policy: DebugText(ctx.policy().validation),
                facts: DebugText(result.facts()),
                bytes_in: result.bytes_in(),
                bytes_out: result.bytes_out(),
            };
            let prepared = output::prepare(
                cli,
                &report,
                "Completed (trusted document timestamp)",
                true,
                ctx,
            )?;
            output::deliver(stage, destination)?;
            prepared.send()?;
            Ok(0)
        }
        TimestampCommand::Verify {
            input,
            data,
            algorithm,
            policy_oid,
            maximum_age_seconds,
        } => {
            let mut request = oncl_core::StampVerifyRequest::new();
            if let Some(algorithm) = algorithm {
                request = request.with_algorithm(algorithm.sdk());
            }
            if let Some(policy) = policy_oid {
                request =
                    request.with_policy(policy.parse().map_err(|_| {
                        ProcessingError::InvalidInput("invalid host timestamp policy")
                    })?);
            }
            if let Some(age) = maximum_age_seconds {
                request = request.with_maximum_age(Duration::from_secs(*age));
            }
            let mut token = Input::open(input)?;
            let mut data = data.as_deref().map(Input::open).transpose()?;
            let result = engine.verify_stamp(
                &request,
                token.source(),
                data.as_mut().map(Input::source),
                ctx,
            )?;
            let (verdict, exit) = reports::verdict(result.verdict());
            let report = Report {
                operation_id: result.id().get(),
                code: "Completed",
                applied: "NotApplied",
                verdict,
                policy: DebugText(ctx.policy().validation),
                facts: DebugText(result.facts()),
                bytes_in: result.bytes_in(),
                bytes_out: result.bytes_out(),
            };
            output::report(cli, &report, verdict, ctx)?;
            Ok(exit)
        }
    }
}
