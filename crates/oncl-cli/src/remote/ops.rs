//! Each command is one typed request item; its answer becomes the same report and exit code
//! the local command produces for the same outcome.
use super::{
    Builder, Failure, Session, container_bytes, core_applied, key_reference, reports, single,
    source_of,
};
use crate::{
    args::{Algorithm, Command, SignArgs, SignProfile, VerifyProfile as CliProfile},
    families::{ExtendArgs, ExtendProfile, InspectArgs, InspectProfile, Level, TimestampCommand},
    jose_args::{JwsCommand, JwtCommand, Serialization},
    output,
    wsse::Soap,
};
use oncl_api::{
    client::{Request, Route, wire::ResultRecord},
    dto::{
        ExtendKind, HashAlgorithm, InspectTarget, JwsFormat, Operation, SignKind, SignWriteMode,
        SoapKind, VerifyProfile,
    },
};
use oncl_core::{OperationError, keys::AppliedState};
use zeroize::Zeroizing;

const REFUSED: &str = "RemoteUnsupported";

fn request(builder: Builder, route: Route) -> Result<Request, Failure> {
    builder
        .request(route)
        .map_err(|error| Failure::client(&error, None))
}
fn label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}
fn hash_algorithm(algorithm: Algorithm) -> HashAlgorithm {
    match algorithm {
        Algorithm::Sha256 => HashAlgorithm::Sha256,
        Algorithm::Gost2004 => HashAlgorithm::Gost34311,
        Algorithm::Gost2015_512 => HashAlgorithm::Streebog512,
    }
}
fn soap(version: Soap) -> SoapKind {
    match version {
        Soap::Soap11 => SoapKind::Soap11,
        Soap::Soap12 => SoapKind::Soap12,
    }
}
fn verify_profile(profile: CliProfile) -> VerifyProfile {
    match profile {
        CliProfile::Cms => VerifyProfile::Cms,
        CliProfile::Xml => VerifyProfile::Xml,
        CliProfile::XmlKalkan => VerifyProfile::XmlKalkan,
        CliProfile::Wsse => VerifyProfile::Wsse,
        CliProfile::Pdf => VerifyProfile::Pdf,
        CliProfile::CadesB => VerifyProfile::CadesB,
        CliProfile::CadesT => VerifyProfile::CadesT,
        CliProfile::CadesLt => VerifyProfile::CadesLt,
        CliProfile::CadesLta => VerifyProfile::CadesLta,
        CliProfile::XadesB => VerifyProfile::XadesB,
        CliProfile::XadesT => VerifyProfile::XadesT,
        CliProfile::XadesLt => VerifyProfile::XadesLt,
        CliProfile::XadesLta => VerifyProfile::XadesLta,
        CliProfile::PadesB => VerifyProfile::PadesB,
        CliProfile::PadesT => VerifyProfile::PadesT,
        CliProfile::PadesLt => VerifyProfile::PadesLt,
        CliProfile::PadesLta => VerifyProfile::PadesLta,
    }
}
fn jws_format(serialization: Serialization) -> JwsFormat {
    match serialization {
        Serialization::Compact => JwsFormat::Compact,
        Serialization::Flattened => JwsFormat::Flattened,
        Serialization::General => JwsFormat::General,
    }
}
/// The signing profile the HTTP contract names for a CLI profile; `Err` for a profile the
/// contract does not have (raw/digest signing, and XAdES LT/LTA, which are sign `xades-t`
/// followed by a keyless `extend`).
pub fn sign_kind(args: &SignArgs) -> Result<SignKind, &'static str> {
    use SignProfile as P;
    let legacy = args.legacy.legacy;
    Ok(match (args.profile, legacy) {
        (P::Cms, false) => SignKind::Cms,
        (P::Xml, false) => SignKind::Xml,
        (P::Xml, true) => SignKind::XmlLegacy,
        (P::Wsse, false) => SignKind::Wsse,
        (P::XadesB, false) => SignKind::XadesB,
        (P::XadesB, true) => SignKind::XadesLegacyB,
        (P::XadesT, false) => SignKind::XadesT,
        (P::XadesT, true) => SignKind::XadesLegacyT,
        (P::Pdf, false) => SignKind::Pdf,
        (P::PadesB, false) => SignKind::PadesB,
        (P::PadesT, false) => SignKind::PadesT,
        (P::PadesLt, false) => SignKind::PadesLt,
        (P::PadesLta, false) => SignKind::PadesLta,
        (P::CadesB, false) => SignKind::CadesB,
        (P::CadesT, false) => SignKind::CadesT,
        (P::CadesLt, false) => SignKind::CadesLt,
        (P::CadesLta, false) => SignKind::CadesLta,
        _ => return Err(REFUSED),
    })
}
fn takes_evidence(kind: SignKind) -> bool {
    matches!(
        kind,
        SignKind::CadesB
            | SignKind::CadesT
            | SignKind::CadesLt
            | SignKind::CadesLta
            | SignKind::PadesB
            | SignKind::PadesT
            | SignKind::PadesLt
            | SignKind::PadesLta
    )
}

pub fn run(s: &mut Session<'_>) -> Result<i32, Failure> {
    let cli = s.cli;
    match &cli.command {
        Command::Hash { algorithm, input } => hash(s, *algorithm, input),
        Command::Verify {
            profile,
            input,
            detached,
            wsse,
            ..
        } => verify(s, *profile, input, detached.as_deref(), wsse.soap_version),
        Command::Extract { input, output } => extract(s, input, output),
        Command::Sign(args) => sign(s, args),
        Command::Inspect(args) => inspect(s, args),
        Command::Extend(args) => extend(s, args),
        Command::Timestamp { command } => timestamp(s, command),
        Command::Batch { command } => super::batch::run(s, command),
        Command::Jws { command } => jws(s, command),
        Command::Jwt { command } => jwt(s, command),
        // Refused by `preflight` before any I/O.
        Command::Plugin { .. } => Err(OperationError::InvalidKeySource.into()),
    }
}

fn hash(s: &mut Session<'_>, algorithm: Algorithm, input: &str) -> Result<i32, Failure> {
    let cli = s.cli;
    let mut builder = Builder::default();
    let part = builder.document("op", source_of(input)?);
    builder.item(
        "op",
        Operation::Hash {
            algorithm: hash_algorithm(algorithm),
            input: part,
        },
    );
    let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
    let (id, item) = single(&reply.record, false)?;
    let ResultRecord::Hash {
        digest, bytes_in, ..
    } = &item.result
    else {
        return Err(Failure::protocol(AppliedState::NotApplied));
    };
    output::report(
        cli,
        &reports::Hash {
            operation_id: id,
            code: "Completed",
            applied: "NotApplied",
            digest,
            bytes_in: *bytes_in,
        },
        digest,
        &mut s.ctx,
    )?;
    Ok(0)
}

fn verify(
    s: &mut Session<'_>,
    profile: CliProfile,
    input: &str,
    detached: Option<&str>,
    soap_version: Option<Soap>,
) -> Result<i32, Failure> {
    let cli = s.cli;
    let mut builder = Builder::default();
    let input = builder.document("op", source_of(input)?);
    let detached = match detached {
        Some(path) => Some(builder.document("op", source_of(path)?)),
        None => None,
    };
    builder.item(
        "op",
        Operation::Verify {
            profile: verify_profile(profile),
            input,
            detached,
            soap: soap_version.map(soap),
        },
    );
    let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
    let (id, item) = single(&reply.record, false)?;
    let ResultRecord::Verification {
        verdict,
        policy,
        checked_at_unix,
        signers,
        ..
    } = &item.result
    else {
        return Err(Failure::protocol(AppliedState::NotApplied));
    };
    let (text, exit) =
        reports::verdict(verdict).ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
    output::report(
        cli,
        &reports::Verification {
            operation_id: id,
            code: "Completed",
            applied: "NotApplied",
            verdict: text,
            policy,
            checked_at: *checked_at_unix,
            signers: signers.iter().map(reports::Signer::from).collect(),
        },
        text,
        &mut s.ctx,
    )?;
    Ok(exit)
}

fn extract(s: &mut Session<'_>, input: &str, destination: &str) -> Result<i32, Failure> {
    let cli = s.cli;
    let store = output::store(cli, destination)?;
    let mut builder = Builder::default();
    let part = builder.document("op", source_of(input)?);
    builder.item("op", Operation::Extract { input: part });
    let mut reply = s.call(request(builder, Route::Operations)?, 1, Some(&store))?;
    let (id, item) = single(&reply.record, false)?;
    let ResultRecord::Extraction { artifact, .. } = &item.result else {
        return Err(Failure::protocol(AppliedState::NotApplied));
    };
    let (id, artifact) = (id, artifact.clone());
    let stage = reply
        .take(artifact.as_deref())
        .ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
    let bytes_out = stage.len();
    let prepared = output::prepare(
        cli,
        &reports::Extracted {
            operation_id: id,
            code: "Completed",
            applied: "NotApplied",
            bytes_out,
            verified: false,
        },
        "Completed (unverified extraction)",
        true,
        &mut s.ctx,
    )?;
    output::deliver(stage, destination)?;
    prepared.send()?;
    Ok(0)
}

/// The facts of a private write that come from the terminal record.
struct WrittenMeta<'a> {
    id: u64,
    applied: oncl_api::error::AppliedState,
    profile: &'a str,
    signers: usize,
}

/// Completes a private write: the staged result and its report are admitted first, the
/// artifact is published, then the report is delivered (a later report failure never undoes
/// a published file and is reported with the honest applied state). The byte counts are the
/// exact ones this client observed: the document bytes it sent and the artifact it received.
fn finish_written(
    s: &mut Session<'_>,
    mut reply: super::Reply,
    artifact: Option<&str>,
    meta: WrittenMeta<'_>,
    destination: &str,
) -> Result<(), Failure> {
    let cli = s.cli;
    let applied = core_applied(meta.applied);
    let uploaded = reply.document_bytes;
    let stage = reply
        .take(artifact)
        .ok_or_else(|| Failure::protocol(applied))?;
    let report = reports::Written {
        operation_id: meta.id,
        code: "Completed",
        applied: reports::applied(meta.applied),
        profile: meta.profile,
        bytes_in: uploaded,
        bytes_out: stage.len(),
        signer_count: meta.signers,
    };
    let prepared = output::prepare(cli, &report, "Completed", true, &mut s.ctx);
    output::finish_artifact(stage, destination, prepared, applied)?;
    Ok(())
}

fn sign(s: &mut Session<'_>, args: &SignArgs) -> Result<i32, Failure> {
    let cli = s.cli;
    let kind = sign_kind(args).map_err(|_| Failure::from(OperationError::InvalidKeySource))?;
    // The destination store exists before the key is used, like the local command.
    let store = output::store(cli, &args.output)?;
    let mut builder = Builder::default();
    let stdin_document = args.input == "-" || args.detached_input.as_deref() == Some("-");
    let key = key_reference(
        &mut builder,
        "op",
        &args.key_options,
        stdin_document,
        &mut s.ctx,
    )?;
    let input = builder.document("op", source_of(&args.input)?);
    let detached = match &args.detached_input {
        Some(path) => Some(builder.document("op", source_of(path)?)),
        None => None,
    };
    let evidence = if takes_evidence(kind) {
        builder.evidence("op", cli)?
    } else {
        Vec::new()
    };
    let cms_family = matches!(
        kind,
        SignKind::Cms
            | SignKind::CadesB
            | SignKind::CadesT
            | SignKind::CadesLt
            | SignKind::CadesLta
    );
    builder.item(
        "op",
        Operation::Sign {
            profile: kind,
            input,
            detached,
            mode: if args.add {
                SignWriteMode::Add
            } else {
                SignWriteMode::Create
            },
            attached: cms_family && !args.detached,
            target: args.target_id.clone(),
            parent: args.parent_id.clone(),
            signature_id: args.signature_id.clone(),
            soap: args.wsse.soap_version.map(soap),
            body_id: args.wsse.wsse_body_id.clone(),
            element: args.legacy.legacy_element.clone(),
            xpath_parent: args.legacy.legacy_parent.clone(),
            signature_method: args
                .legacy
                .legacy_signature_method
                .map(|a| a.signature_uri().to_owned()),
            digest_method: args
                .legacy
                .legacy_digest_method
                .map(|a| a.digest_uri().to_owned()),
            evidence,
            keys: vec![key],
        },
    );
    let reply = s.call(request(builder, Route::Operations)?, 1, Some(&store))?;
    let (id, item) = single(&reply.record, true)?;
    let ResultRecord::Signing {
        profile,
        artifact,
        signers,
        ..
    } = &item.result
    else {
        return Err(Failure::protocol(AppliedState::Unknown));
    };
    let (artifact, profile_text, signer_count, wire_applied) = (
        artifact.clone(),
        label(profile),
        signers.len(),
        item.applied,
    );
    finish_written(
        s,
        reply,
        artifact.as_deref(),
        WrittenMeta {
            id,
            applied: wire_applied,
            profile: &profile_text,
            signers: signer_count,
        },
        &args.output,
    )?;
    Ok(0)
}

fn inspect(s: &mut Session<'_>, args: &InspectArgs) -> Result<i32, Failure> {
    let cli = s.cli;
    let mut builder = Builder::default();
    let input = args.input.as_deref();
    let target = match args.profile {
        InspectProfile::Certificate | InspectProfile::Cms => {
            let part = builder.document(
                "op",
                source_of(input.ok_or(OperationError::InvalidKeySource)?)?,
            );
            if matches!(args.profile, InspectProfile::Cms) {
                InspectTarget::Cms { input: part }
            } else {
                InspectTarget::Certificate { input: part }
            }
        }
        InspectProfile::Container => {
            let path = input.ok_or(OperationError::InvalidKeySource)?;
            let _secret_memory = s.ctx.resources().reserve_memory(16384)?;
            let password = crate::secrets::read(
                args.secret_file.as_deref(),
                args.secret_interactive,
                path == "-",
                &mut s.ctx,
            )?;
            let container = builder.secret("op", container_bytes(path)?);
            let password = builder.secret("op", Zeroizing::new(password.as_bytes().to_vec()));
            InspectTarget::Container {
                container,
                password: Some(password),
            }
        }
        InspectProfile::NamedKey => InspectTarget::Named {
            name: args
                .key_name
                .clone()
                .ok_or(OperationError::InvalidKeySource)?,
        },
    };
    builder.item("op", Operation::Inspect { target });
    let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
    let (id, item) = single(&reply.record, false)?;
    let ResultRecord::Inspection {
        target,
        integrity,
        entries,
        cms,
        ..
    } = &item.result
    else {
        return Err(Failure::protocol(AppliedState::NotApplied));
    };
    output::report(
        cli,
        &reports::Inspection::new(
            id,
            "NotApplied",
            target,
            integrity.as_deref(),
            entries,
            cms.as_ref(),
        ),
        "Completed (structural metadata; not validation)",
        &mut s.ctx,
    )?;
    Ok(0)
}

fn extend(s: &mut Session<'_>, args: &ExtendArgs) -> Result<i32, Failure> {
    let cli = s.cli;
    let kind = match (args.profile, args.level) {
        (ExtendProfile::Cms, Level::T) => ExtendKind::CadesT,
        (ExtendProfile::Cms, Level::Lt) => ExtendKind::CadesLt,
        (ExtendProfile::Cms, Level::Lta) => ExtendKind::CadesLta,
        (ExtendProfile::Pdf, Level::T) => ExtendKind::PadesT,
        (ExtendProfile::Pdf, Level::Lt) => ExtendKind::PadesLt,
        (ExtendProfile::Pdf, Level::Lta) => ExtendKind::PadesLta,
        (ExtendProfile::Xml, Level::Lt) => ExtendKind::XadesLt,
        (ExtendProfile::Xml, Level::Lta) => ExtendKind::XadesLta,
        _ => return Err(OperationError::InvalidKeySource.into()),
    };
    let store = output::store(cli, &args.output)?;
    let mut builder = Builder::default();
    let input = builder.document("op", source_of(&args.input)?);
    let detached = match &args.detached {
        Some(path) => Some(builder.document("op", source_of(path)?)),
        None => None,
    };
    let evidence = builder.evidence("op", cli)?;
    builder.item(
        "op",
        Operation::Extend {
            profile: kind,
            input,
            detached,
            evidence,
        },
    );
    let mut reply = s.call(request(builder, Route::Operations)?, 1, Some(&store))?;
    let (id, item) = single(&reply.record, false)?;
    let ResultRecord::Extension {
        profile,
        artifact,
        verdicts,
        ..
    } = &item.result
    else {
        return Err(Failure::protocol(AppliedState::NotApplied));
    };
    let profile = label(profile);
    let (bytes_in, signers, artifact) = (reply.document_bytes, verdicts.len(), artifact.clone());
    let stage = reply
        .take(artifact.as_deref())
        .ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
    let bytes_out = stage.len();
    let prepared = output::prepare(
        cli,
        &reports::Written {
            operation_id: id,
            code: "Completed",
            applied: "NotApplied",
            profile: &profile,
            bytes_in,
            bytes_out,
            signer_count: signers,
        },
        "Completed (public evidence extension)",
        true,
        &mut s.ctx,
    )?;
    output::deliver(stage, &args.output)?;
    prepared.send()?;
    Ok(0)
}

fn timestamp(s: &mut Session<'_>, command: &TimestampCommand) -> Result<i32, Failure> {
    let cli = s.cli;
    match command {
        TimestampCommand::Acquire { input, output, .. } => {
            let store = output::store(cli, output)?;
            let mut builder = Builder::default();
            let part = builder.document("op", source_of(input)?);
            builder.item("op", Operation::Stamp { input: part });
            let mut reply = s.call(request(builder, Route::Operations)?, 1, Some(&store))?;
            let (id, item) = single(&reply.record, false)?;
            let ResultRecord::Stamping {
                artifact,
                timestamp,
                ..
            } = &item.result
            else {
                return Err(Failure::protocol(AppliedState::NotApplied));
            };
            let (artifact, facts, bytes_in) =
                (artifact.clone(), timestamp.clone(), reply.document_bytes);
            let stage = reply
                .take(artifact.as_deref())
                .ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
            let bytes_out = stage.len();
            let prepared = output::prepare(
                cli,
                &reports::Timestamp::new(id, &facts, bytes_in, bytes_out),
                "Completed (trusted document timestamp)",
                true,
                &mut s.ctx,
            )?;
            output::deliver(stage, output)?;
            prepared.send()?;
            Ok(0)
        }
        TimestampCommand::Verify {
            input,
            data,
            algorithm,
            maximum_age_seconds,
            ..
        } => {
            let mut builder = Builder::default();
            let token = builder.document("op", source_of(input)?);
            let data = match data {
                Some(path) => Some(builder.document("op", source_of(path)?)),
                None => None,
            };
            builder.item(
                "op",
                Operation::VerifyStamp {
                    token,
                    data,
                    algorithm: algorithm.map(hash_algorithm),
                    max_age_seconds: *maximum_age_seconds,
                },
            );
            let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
            let (id, item) = single(&reply.record, false)?;
            let ResultRecord::StampVerification { timestamp, .. } = &item.result else {
                return Err(Failure::protocol(AppliedState::NotApplied));
            };
            let (text, exit) = reports::verdict(&timestamp.verdict)
                .ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
            output::report(
                cli,
                &reports::Timestamp::new(id, timestamp, reply.document_bytes, 0),
                text,
                &mut s.ctx,
            )?;
            Ok(exit)
        }
    }
}

fn jws(s: &mut Session<'_>, command: &JwsCommand) -> Result<i32, Failure> {
    let cli = s.cli;
    match command {
        JwsCommand::Verify(args) => {
            let mut builder = Builder::default();
            let input = builder.document("op", source_of(&args.input)?);
            let detached = match &args.detached_input {
                Some(path) => Some(builder.document("op", source_of(path)?)),
                None => None,
            };
            let certificate = match &args.certificate {
                Some(path) => Some(builder.document("op", source_of(super::path_text(path)?)?)),
                None => None,
            };
            builder.item(
                "op",
                Operation::JwsVerify {
                    serialization: jws_format(args.serialization),
                    input,
                    detached,
                    certificate,
                },
            );
            let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
            let (id, item) = single(&reply.record, false)?;
            let ResultRecord::JwsVerification {
                verdict,
                policy,
                checked_at_unix,
                signers,
            } = &item.result
            else {
                return Err(Failure::protocol(AppliedState::NotApplied));
            };
            let (text, exit) = reports::verdict(verdict)
                .ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
            output::report(
                cli,
                &reports::JwsVerification {
                    operation_id: id,
                    code: "Completed",
                    applied: "NotApplied",
                    verdict: text,
                    policy,
                    checked_at: *checked_at_unix,
                    signers: signers.iter().map(reports::JwsSigner::from).collect(),
                },
                text,
                &mut s.ctx,
            )?;
            Ok(exit)
        }
        JwsCommand::Sign(args) => {
            let store = output::store(cli, &args.output)?;
            let mut builder = Builder::default();
            let stdin_document = args.input == "-" || args.detached_input.as_deref() == Some("-");
            let key = key_reference(&mut builder, "op", &args.key, stdin_document, &mut s.ctx)?;
            let input = builder.document("op", source_of(&args.input)?);
            let detached_part = match &args.detached_input {
                Some(path) => Some(builder.document("op", source_of(path)?)),
                None => None,
            };
            let certificate = match &args.certificate {
                Some(path) => Some(builder.document("op", source_of(super::path_text(path)?)?)),
                None => None,
            };
            let serialization = jws_format(args.serialization);
            builder.item(
                "op",
                if args.add {
                    Operation::JwsAdd {
                        serialization,
                        input,
                        detached: detached_part,
                        certificate,
                        keys: vec![key],
                    }
                } else {
                    Operation::JwsSign {
                        serialization,
                        detached: args.detached,
                        input,
                        keys: vec![key],
                    }
                },
            );
            let reply = s.call(request(builder, Route::Operations)?, 1, Some(&store))?;
            written_jose(
                s,
                reply,
                if args.add {
                    "JwsGeneralAdd"
                } else {
                    "JwsCreate"
                },
                &args.output,
            )
        }
    }
}

fn written_jose(
    s: &mut Session<'_>,
    reply: super::Reply,
    profile: &str,
    destination: &str,
) -> Result<i32, Failure> {
    let (id, item) = single(&reply.record, true)?;
    let ResultRecord::Jws {
        artifact, signers, ..
    } = &item.result
    else {
        return Err(Failure::protocol(AppliedState::Unknown));
    };
    let (artifact, profile_text, signer_count, wire_applied) = (
        artifact.clone(),
        profile.to_owned(),
        signers.len(),
        item.applied,
    );
    finish_written(
        s,
        reply,
        artifact.as_deref(),
        WrittenMeta {
            id,
            applied: wire_applied,
            profile: &profile_text,
            signers: signer_count,
        },
        destination,
    )?;
    Ok(0)
}

fn jwt(s: &mut Session<'_>, command: &JwtCommand) -> Result<i32, Failure> {
    let cli = s.cli;
    match command {
        JwtCommand::Encode(args) => {
            let store = output::store(cli, &args.output)?;
            let mut builder = Builder::default();
            let key = key_reference(&mut builder, "op", &args.key, args.input == "-", &mut s.ctx)?;
            let input = builder.document("op", source_of(&args.input)?);
            builder.item("op", Operation::JwtEncode { input, key });
            let reply = s.call(request(builder, Route::Operations)?, 1, Some(&store))?;
            written_jose(s, reply, "JwtEncode", &args.output)
        }
        JwtCommand::Verify(args) => {
            let mut builder = Builder::default();
            let input = builder.document("op", source_of(&args.input)?);
            let certificate = match &args.certificate {
                Some(path) => Some(builder.document("op", source_of(super::path_text(path)?)?)),
                None => None,
            };
            builder.item("op", Operation::JwtVerify { input, certificate });
            let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
            let (id, item) = single(&reply.record, false)?;
            let ResultRecord::JwtVerification {
                verdict,
                signature_verdict,
                claims_verdict,
                claim_failures,
                checked_at_unix,
                signers,
                ..
            } = &item.result
            else {
                return Err(Failure::protocol(AppliedState::NotApplied));
            };
            let (text, exit) = reports::verdict(verdict)
                .ok_or_else(|| Failure::protocol(AppliedState::NotApplied))?;
            output::report(
                cli,
                &reports::JwtVerification {
                    operation_id: id,
                    code: "Completed",
                    applied: "NotApplied",
                    verdict: text,
                    jws: reports::JwtJws {
                        verdict: signature_verdict,
                        checked_at: *checked_at_unix,
                        signers: signers.iter().map(reports::JwsSigner::from).collect(),
                    },
                    claims: reports::JwtClaims {
                        verdict: claims_verdict,
                        checked_at: *checked_at_unix,
                        failures: claim_failures,
                    },
                },
                text,
                &mut s.ctx,
            )?;
            Ok(exit)
        }
        JwtCommand::Decode {
            input,
            output: destination,
        } => {
            let store = output::store(cli, destination)?;
            let mut builder = Builder::default();
            let part = builder.document("op", source_of(input)?);
            builder.item("op", Operation::JwtDecode { input: part });
            let reply = s.call(request(builder, Route::Operations)?, 0, None)?;
            let (id, item) = single(&reply.record, false)?;
            let ResultRecord::JwtDecoded {
                verified, claims, ..
            } = &item.result
            else {
                return Err(Failure::protocol(AppliedState::NotApplied));
            };
            // The payload travels in the record (JSON text); it becomes the output file.
            let mut stage = store
                .stage(s.ctx.resources())
                .map_err(OperationError::from)?;
            stage
                .write_chunk(claims.as_bytes())
                .map_err(OperationError::from)?;
            let prepared = output::prepare(
                cli,
                &reports::DecodedJwt {
                    operation_id: id,
                    code: "Completed",
                    verified: *verified,
                    bytes_out: claims.len(),
                },
                "Completed (unverified JWT decode)",
                true,
                &mut s.ctx,
            );
            output::finish_artifact(stage, destination, prepared, AppliedState::NotApplied)?;
            Ok(0)
        }
    }
}
