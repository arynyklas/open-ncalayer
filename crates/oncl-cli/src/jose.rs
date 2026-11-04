use crate::{
    args::{Cli, PrivateKeyArgs},
    bounded,
    jose_args::*,
    local::Input,
    output,
    reports::{self, DebugText},
    secrets,
};
use oncl_core::{
    Engine, OperationContext, OperationError,
    jose::{self, JoseWriteReport, JwsVerificationReport, JwsVerifyRequest, JwtVerificationReport},
    keys::{AppliedState, KeyRequest, KeySelector},
};
use oncl_pki::{
    cert::Certificate,
    resource::{ProcessingError, ResourceReservation},
};
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use std::path::Path;

struct PublicCertificate {
    certificate: Certificate,
    _encoded: bounded::Bytes,
    _memory: ResourceReservation,
}
fn certificate(
    path: Option<&Path>,
    ctx: &mut OperationContext,
) -> Result<Option<PublicCertificate>, OperationError> {
    path.map(|path| {
        let path = path.to_str().ok_or(ProcessingError::InvalidInput(
            "non-Unicode certificate path",
        ))?;
        let mut input = Input::open(path)?;
        let encoded = bounded::read(input.source(), 8192, ctx)?;
        let memory = ctx.resources().reserve_metadata(
            (encoded.as_bytes().len() as u64)
                .checked_mul(crate::bounded::CERTIFICATE_METADATA_FACTOR)
                .ok_or(ProcessingError::MetadataLimit)?,
        )?;
        let certificate = oncl_pki::cert::parse(encoded.as_bytes())
            .map_err(|_| ProcessingError::InvalidInput("invalid host signer certificate"))?;
        Ok(PublicCertificate {
            certificate,
            _encoded: encoded,
            _memory: memory,
        })
    })
    .transpose()
}
fn input(
    path: &str,
    maximum: usize,
    ctx: &mut OperationContext,
) -> Result<bounded::Bytes, OperationError> {
    let mut input = Input::open(path)?;
    bounded::read(input.source(), maximum, ctx)
}
fn secret(
    args: &PrivateKeyArgs,
    stdin_document: bool,
    ctx: &mut OperationContext,
) -> Result<zeroize::Zeroizing<String>, OperationError> {
    secrets::read(
        args.secret_file.as_deref(),
        args.secret_interactive,
        stdin_document,
        ctx,
    )
}
struct Signers<'a>(&'a [jose::JoseSignerReport]);
impl Serialize for Signers<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Signer<'a> {
            algorithm: &'static str,
            crypto: DebugText<oncl_pki::validation::CheckStatus>,
            trust: reports::Signer<'a>,
        }
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for signer in self.0 {
            sequence.serialize_element(&Signer {
                algorithm: signer.algorithm().name(),
                crypto: DebugText(signer.crypto()),
                trust: reports::Signer(signer.trust()),
            })?;
        }
        sequence.end()
    }
}
struct Verification<'a>(&'a JwsVerificationReport);
impl Serialize for Verification<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let report = self.0;
        let mut m = serializer.serialize_map(None)?;
        m.serialize_entry("code", "Completed")?;
        m.serialize_entry("applied", "NotApplied")?;
        m.serialize_entry("verdict", reports::verdict(report.verdict()).0)?;
        m.serialize_entry("policy", &DebugText(report.policy()))?;
        m.serialize_entry("checked_at", &report.checked_at().unix_timestamp())?;
        m.serialize_entry("payload_bytes", &report.payload().len())?;
        m.serialize_entry("signers", &Signers(report.signers()))?;
        m.end()
    }
}
struct JwtVerification<'a>(&'a JwtVerificationReport);
impl Serialize for JwtVerification<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Claims<'a> {
            verdict: &'static str,
            checked_at: i64,
            failures: DebugText<&'a [jose::ClaimsFailure]>,
        }
        let mut m = serializer.serialize_map(None)?;
        m.serialize_entry("code", "Completed")?;
        m.serialize_entry("applied", "NotApplied")?;
        m.serialize_entry("verdict", reports::verdict(self.0.verdict()).0)?;
        m.serialize_entry("jws", &Verification(self.0.jws()))?;
        m.serialize_entry(
            "claims",
            &Claims {
                verdict: reports::verdict(self.0.claims().verdict()).0,
                checked_at: self.0.claims().checked_at(),
                failures: DebugText(self.0.claims().failures()),
            },
        )?;
        m.end()
    }
}
fn written(
    engine_result: &JoseWriteReport,
    profile: &'static str,
    stage: oncl_pki::io::StagedArtifact,
    destination: &str,
    cli: &Cli,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    #[derive(Serialize)]
    struct Report {
        operation_id: u64,
        code: &'static str,
        profile: &'static str,
        applied: DebugText<AppliedState>,
        bytes_in: u64,
        bytes_out: u64,
        signer_count: usize,
    }
    let report = Report {
        operation_id: ctx.id().get(),
        code: "Completed",
        profile,
        applied: DebugText(engine_result.applied),
        bytes_in: engine_result.bytes_in,
        bytes_out: engine_result.bytes_out,
        signer_count: engine_result.signer_count,
    };
    let prepared = output::prepare(cli, &report, "Completed", true, ctx);
    output::finish_artifact(stage, destination, prepared, engine_result.applied)?;
    Ok(0)
}
pub fn jws(
    engine: &Engine,
    command: &JwsCommand,
    cli: &Cli,
    selector: Option<&KeySelector>,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    match command {
        JwsCommand::Verify(args) => {
            let certificate = certificate(args.certificate.as_deref(), ctx)?;
            let wire = input(&args.input, jose::MAX_CONTAINER_BYTES, ctx)?;
            let detached = args
                .detached_input
                .as_deref()
                .map(|path| input(path, jose::MAX_PAYLOAD_BYTES, ctx))
                .transpose()?;
            let request = JwsVerifyRequest {
                profile: args.serialization.profile(detached.is_some()),
                certificate: certificate.as_ref().map(|c| &c.certificate),
            };
            let result = engine.jws_verify(
                request,
                wire.as_bytes(),
                detached.as_ref().map(bounded::Bytes::as_bytes),
                ctx,
            )?;
            let (verdict, exit) = reports::verdict(result.verdict());
            output::report(cli, &Verification(&result), verdict, ctx)?;
            Ok(exit)
        }
        JwsCommand::Sign(args) => {
            let _secret_memory = ctx.resources().reserve_memory(16384)?;
            let secret = secret(
                &args.key,
                args.input == "-" || args.detached_input.as_deref() == Some("-"),
                ctx,
            )?;
            let selector = selector.ok_or(OperationError::InvalidKeySource)?;
            let wire = input(
                &args.input,
                if args.add {
                    jose::MAX_CONTAINER_BYTES
                } else {
                    jose::MAX_PAYLOAD_BYTES
                },
                ctx,
            )?;
            let detached = args
                .detached_input
                .as_deref()
                .map(|path| input(path, jose::MAX_PAYLOAD_BYTES, ctx))
                .transpose()?;
            let certificate = certificate(args.certificate.as_deref(), ctx)?;
            let profile = args
                .serialization
                .profile(args.detached || detached.is_some());
            let store = output::store(cli, &args.output)?;
            let mut stage = store.stage(ctx.resources())?;
            let request = KeyRequest::new(selector, Some(secret.as_str()));
            let result = if args.add {
                engine.jws_add_staged(
                    JwsVerifyRequest {
                        profile,
                        certificate: certificate.as_ref().map(|c| &c.certificate),
                    },
                    vec![request],
                    wire.as_bytes(),
                    detached.as_ref().map(bounded::Bytes::as_bytes),
                    &mut stage,
                    ctx,
                )?
            } else {
                engine.jws_create_staged(
                    profile,
                    vec![request],
                    wire.as_bytes(),
                    &mut stage,
                    ctx,
                )?
            };
            written(
                &result,
                if args.add {
                    "JwsGeneralAdd"
                } else {
                    "JwsCreate"
                },
                stage,
                &args.output,
                cli,
                ctx,
            )
        }
    }
}
pub fn jwt(
    engine: &Engine,
    command: &JwtCommand,
    cli: &Cli,
    selector: Option<&KeySelector>,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    match command {
        JwtCommand::Encode(args) => {
            let _secret_memory = ctx.resources().reserve_memory(16384)?;
            let secret = secret(&args.key, args.input == "-", ctx)?;
            let claims = input(&args.input, jose::MAX_CLAIMS_BYTES, ctx)?;
            let store = output::store(cli, &args.output)?;
            let mut stage = store.stage(ctx.resources())?;
            let result = engine.jwt_encode_staged(
                KeyRequest::new(
                    selector.ok_or(OperationError::InvalidKeySource)?,
                    Some(secret.as_str()),
                ),
                claims.as_bytes(),
                &mut stage,
                ctx,
            )?;
            written(&result, "JwtEncode", stage, &args.output, cli, ctx)
        }
        JwtCommand::Verify(args) => {
            let certificate = certificate(args.certificate.as_deref(), ctx)?;
            let wire = input(&args.input, jose::MAX_CONTAINER_BYTES, ctx)?;
            let mut policy = jose::JwtValidationPolicy::new(
                cli.as_of
                    .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp()),
            );
            policy.expected_issuer = args.issuer.clone();
            policy.expected_audience = args.audience.clone();
            policy.leeway_seconds = args.leeway_seconds;
            let result = engine.jwt_verify(
                certificate.as_ref().map(|c| &c.certificate),
                wire.as_bytes(),
                &policy,
                ctx,
            )?;
            let (verdict, exit) = reports::verdict(result.verdict());
            output::report(cli, &JwtVerification(&result), verdict, ctx)?;
            Ok(exit)
        }
        JwtCommand::Decode {
            input: path,
            output: destination,
        } => {
            let wire = input(path, jose::MAX_CONTAINER_BYTES, ctx)?;
            let result = engine.jwt_decode_unverified(wire.as_bytes(), ctx)?;
            let store = output::store(cli, destination)?;
            let mut stage = store.stage(ctx.resources())?;
            stage.write_chunk(result.payload())?;
            #[derive(Serialize)]
            struct Report {
                operation_id: u64,
                code: &'static str,
                verified: bool,
                bytes_out: usize,
            }
            let report = Report {
                operation_id: ctx.id().get(),
                code: "Completed",
                verified: result.is_verified(),
                bytes_out: result.payload().len(),
            };
            let prepared =
                output::prepare(cli, &report, "Completed (unverified JWT decode)", true, ctx);
            output::finish_artifact(stage, destination, prepared, AppliedState::NotApplied)?;
            Ok(0)
        }
    }
}
