//! `batch run --endpoint`: the manifest is host data read here; every source is streamed
//! from this client; the server runs the closed batch (`POST /v1/batch`) and the client
//! publishes each finished output only after the complete terminal record.
//!
//! A source that cannot be opened fails only its own item (the others still run), exactly
//! like the local batch. After a lost terminal record nothing is published, no automatic
//! retry exists and earlier files at other paths are never touched.
use super::{
    Builder, Failure, Session, container_bytes, core_applied, reports, source_from_input,
    take_artifact,
};
use crate::{
    batch::{
        BatchCommand, Digest, Item, MANIFEST_BYTES, Report, Row, SignProfile, human, parse,
        worst_verdict,
    },
    bounded,
    local::Input,
    output, secrets,
};
use oncl_api::{
    client::{FinalRecord, Route, wire::ResultRecord},
    dto::{
        BatchItemOutcome, BatchStatus, BatchStopKind, HashAlgorithm, KeyRef, Operation, SignKind,
        SignWriteMode, VerifyProfile,
    },
};
use oncl_core::{OperationError, keys::AppliedState};
use oncl_pki::{
    io::{StagedArtifact, TemporaryStore},
    resource::ProcessingError,
};
use std::{collections::HashSet, path::Path};
use zeroize::Zeroizing;

fn algorithm(value: &crate::batch::Algorithm) -> HashAlgorithm {
    match value {
        crate::batch::Algorithm::Sha256 => HashAlgorithm::Sha256,
        crate::batch::Algorithm::Gost2004 => HashAlgorithm::Gost34311,
        crate::batch::Algorithm::Gost2015_512 => HashAlgorithm::Streebog512,
    }
}
fn digest_name(value: HashAlgorithm) -> &'static str {
    match value {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Gost34311 => "gost2004",
        HashAlgorithm::Streebog512 => "gost2015-512",
        _ => "other",
    }
}

pub fn run(s: &mut Session<'_>, command: &BatchCommand) -> Result<i32, Failure> {
    let cli = s.cli;
    let args = command.args();
    let mut manifest_input = Input::open(
        args.manifest
            .to_str()
            .ok_or(ProcessingError::InvalidInput("manifest path"))?,
    )?;
    let raw = bounded::read(manifest_input.source(), MANIFEST_BYTES, &mut s.ctx)?;
    let manifest = parse(raw.as_bytes(), command.has_key())
        .map_err(|code| OperationError::Processing(ProcessingError::InvalidInput(code)))?;
    drop(raw);
    if manifest.items.iter().any(|item| {
        matches!(
            item,
            Item::Sign {
                profile: SignProfile::Raw,
                ..
            }
        )
    }) {
        // Raw signing is not a profile of the HTTP contract.
        return Err(Failure {
            code: "RemoteUnsupported".into(),
            applied: AppliedState::NotApplied,
            cancelled: false,
        });
    }
    // The key of the sign items: the operator's name, or (inline mode) the container and
    // its password, each copied into every sign item as that item's own secret parts.
    let _secret_memory = s.ctx.resources().reserve_memory(16384)?;
    let inline = match (&args.key, &args.key_name) {
        (Some(path), None) => {
            let password = secrets::read(
                args.secret_file.as_deref(),
                args.secret_interactive,
                args.manifest.as_os_str() == "-",
                &mut s.ctx,
            )?;
            Some((
                container_bytes(path.to_str().ok_or(OperationError::InvalidKeySource)?)?,
                Zeroizing::new(password.as_bytes().to_vec()),
            ))
        }
        _ => None,
    };
    let mut builder = Builder::default();
    let mut submitted: Vec<usize> = Vec::new();
    for (index, item) in manifest.items.iter().enumerate() {
        let opened: Vec<Input> = item
            .inputs()
            .iter()
            .map(|path| Input::open_lenient(path))
            .collect();
        if opened
            .iter()
            .any(|input| matches!(input, Input::Unreadable(_)))
        {
            // Fails only this item; the rest of the batch still runs.
            continue;
        }
        let id = format!("i{index}");
        let mut sources = opened.into_iter().map(source_from_input);
        let mut next = |builder: &mut Builder| {
            sources
                .next()
                .map(|source| builder.document(&id, source))
                .ok_or(OperationError::InvalidKeySource)
        };
        let operation = match item {
            Item::Hash { algorithm: a, .. } => Operation::Hash {
                algorithm: algorithm(a),
                input: next(&mut builder)?,
            },
            Item::Verify { detached, .. } => {
                let input = next(&mut builder)?;
                Operation::Verify {
                    profile: VerifyProfile::Cms,
                    input,
                    detached: if detached.is_some() {
                        Some(next(&mut builder)?)
                    } else {
                        None
                    },
                    soap: None,
                }
            }
            Item::Extract { .. } => Operation::Extract {
                input: next(&mut builder)?,
            },
            Item::Sign { profile, .. } => {
                let key = match (&inline, &args.key_name) {
                    (Some((container, password)), _) => KeyRef::Inline {
                        container: builder.secret(&id, container.clone()),
                        password: Some(builder.secret(&id, password.clone())),
                        alias: args.alias.clone(),
                    },
                    (None, Some(name)) => KeyRef::Named { name: name.clone() },
                    _ => return Err(OperationError::InvalidKeySource.into()),
                };
                Operation::Sign {
                    profile: SignKind::Cms,
                    input: next(&mut builder)?,
                    detached: None,
                    mode: SignWriteMode::Create,
                    attached: matches!(profile, SignProfile::Cms),
                    target: None,
                    parent: None,
                    signature_id: None,
                    soap: None,
                    body_id: None,
                    element: None,
                    xpath_parent: None,
                    signature_method: None,
                    digest_method: None,
                    evidence: Vec::new(),
                    keys: vec![key],
                }
            }
        };
        builder.item(&id, operation);
        submitted.push(index);
    }
    let outputs: Vec<&Path> = submitted
        .iter()
        .filter_map(|index| manifest.items[*index].output())
        .collect();
    // One staging store: the shared destination directory (a same-directory link, like the
    // local batch) or, for scattered destinations, the temporary directory option.
    let parents: HashSet<&Path> = outputs.iter().map(|path| output::parent(path)).collect();
    let store = match parents.iter().next() {
        Some(parent) if parents.len() == 1 => {
            TemporaryStore::new(parent).map_err(OperationError::from)?
        }
        _ => output::store(cli, "-")?,
    };
    let local_failures = manifest.items.len() - submitted.len();
    let (final_record, mut artifacts) = if submitted.is_empty() {
        (None, Vec::new())
    } else {
        let request = builder
            .request(Route::Batch)
            .map_err(|error| Failure::client(&error, None))?;
        let reply = s.call(request, outputs.len(), Some(&store))?;
        (Some(reply.record), reply.artifacts)
    };
    let record = final_record.as_ref();
    let (operation_id, completed, attempted, stop, records) = match record {
        Some(FinalRecord::BatchFinal {
            operation_id,
            status,
            attempted,
            completed,
            total,
            stop,
            items,
            error,
        }) => {
            if *status == BatchStatus::Failed
                && let Some(error) = error
            {
                return Err(Failure::record(error));
            }
            let in_order = *total == submitted.len()
                && items.len() == submitted.len()
                && items.iter().enumerate().all(|(position, item)| {
                    item.index == position && item.item_id == format!("i{}", submitted[position])
                });
            if !in_order {
                return Err(Failure::protocol(AppliedState::Unknown));
            }
            (
                *operation_id,
                *completed,
                *attempted,
                stop.as_ref(),
                items.as_slice(),
            )
        }
        None => (0, 0, 0, None, [].as_slice()),
        Some(FinalRecord::Final { .. }) => return Err(Failure::protocol(AppliedState::Unknown)),
    };
    // Resolve every output of a completed item before publishing anything: a record that
    // names a missing artifact publishes nothing.
    let mut destinations: Vec<Option<(&Path, StagedArtifact)>> =
        (0..manifest.items.len()).map(|_| None).collect();
    for (position, index) in submitted.iter().enumerate() {
        let item = &manifest.items[*index];
        let Some(destination) = item.output() else {
            continue;
        };
        let record = &records[position];
        if record.outcome == BatchItemOutcome::Completed {
            let artifact = record
                .result
                .as_ref()
                .and_then(ResultRecord::artifact)
                .map(str::to_owned);
            let stage = take_artifact(&mut artifacts, artifact.as_deref())
                .ok_or_else(|| Failure::protocol(AppliedState::Unknown))?;
            destinations[*index] = Some((destination, stage));
        }
    }
    let mut published = vec![false; manifest.items.len()];
    let mut publication_failure: Option<OperationError> = None;
    for (index, slot) in destinations.iter_mut().enumerate() {
        if let Some((destination, stage)) = slot.take() {
            match stage.commit(destination) {
                Ok(()) => published[index] = true,
                Err(error) => {
                    publication_failure.get_or_insert(error.into());
                }
            }
        }
    }
    let mut worst = 0;
    let mut rows = Vec::new();
    for (index, item) in manifest.items.iter().enumerate() {
        let mut digest = None;
        let (status, code, applied, verdict) = match submitted.iter().position(|i| *i == index) {
            None => ("Failed", "Io".to_owned(), AppliedState::NotApplied, None),
            Some(position) => {
                let record = &records[position];
                match record.outcome {
                    BatchItemOutcome::Completed => {
                        let verdict = match record.verdict.as_deref() {
                            Some(text) => {
                                let (label, rank) = reports::verdict(text)
                                    .ok_or_else(|| Failure::protocol(AppliedState::Unknown))?;
                                worst = worst_verdict(worst, rank);
                                Some(label)
                            }
                            None => None,
                        };
                        if let Some(ResultRecord::Hash {
                            algorithm,
                            digest: hex,
                            ..
                        }) = &record.result
                        {
                            digest = Some(Digest {
                                algorithm: digest_name(*algorithm),
                                hex: hex.clone(),
                            });
                        }
                        (
                            "Completed",
                            "Completed".to_owned(),
                            core_applied(record.applied),
                            verdict,
                        )
                    }
                    BatchItemOutcome::Failed => (
                        "Failed",
                        record
                            .error
                            .as_ref()
                            .map(|error| format!("{:?}", error.code))
                            .unwrap_or_else(|| "Failed".into()),
                        core_applied(record.applied),
                        None,
                    ),
                    BatchItemOutcome::NotRun => (
                        "NotRun",
                        "NotRun".to_owned(),
                        core_applied(record.applied),
                        None,
                    ),
                }
            }
        };
        rows.push(Row {
            id: item.id().to_owned(),
            status,
            code,
            applied: format!("{applied:?}"),
            verdict,
            published: item.output().map(|_| published[index]),
            digest,
        });
    }
    let stop_text = stop.map(|stop| match stop.kind {
        BatchStopKind::Control => format!("{:?}", stop.code),
        BatchStopKind::Item => format!(
            "item {}: {:?}: {:?}",
            stop.item_index
                .and_then(|position| submitted.get(position))
                .copied()
                .unwrap_or_default(),
            stop.code,
            core_applied(stop.applied)
        ),
    });
    let cancelled = stop.is_some_and(|stop| stop.code == oncl_api::error::ErrorCode::Cancelled);
    let deadline =
        stop.is_some_and(|stop| stop.code == oncl_api::error::ErrorCode::DeadlineExceeded);
    let total = manifest.items.len();
    let incomplete = completed != total;
    let report = Report {
        operation_id,
        code: if cancelled {
            "Cancelled"
        } else if deadline {
            "DeadlineExceeded"
        } else if incomplete {
            "Partial"
        } else {
            "Completed"
        },
        attempted: attempted + local_failures,
        completed,
        total,
        stop: stop_text,
        items: rows,
    };
    let text = human(&report);
    output::report(cli, &report, &text, &mut s.ctx)?;
    if let Some(error) = publication_failure {
        // The terminal record said completed, but a file could not be linked into place:
        // an execution failure (the key use it records is real and stays reported).
        let applied = records
            .iter()
            .fold(AppliedState::NotApplied, |state, item| {
                state.combine(core_applied(item.applied))
            });
        return Err(OperationError::AfterKeyUse {
            source: Box::new(error),
            applied,
        }
        .into());
    }
    Ok(if cancelled {
        130
    } else if incomplete {
        4
    } else {
        worst
    })
}
