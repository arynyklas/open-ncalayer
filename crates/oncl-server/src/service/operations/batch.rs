//! `POST /v1/batch`: the SDK closed batch (`capture_batch` -> explicit host approval ->
//! `run_batch_with_outputs`) behind the HTTP service.
//!
//! Authority is never taken from the payload. The operator policy (token x operation x
//! key x batch right) is decided for EVERY item and for the whole composition before a
//! document or secret byte is read (`dispatch::route_precheck`), is re-run once the body
//! is taken, and the SDK `BatchApproval` is produced by [`approve`] only for a captured
//! plan that matches, item by item, the composition the host authorized (ids and order,
//! action, signing profile, resolved keys, captured source bytes). The same ORIGINAL
//! admitted context carries intake, capture, every item and the response.
use super::{
    artifact::{ArtifactStore, ArtifactWriter, FinishedArtifact},
    dispatch::{self, requests, results},
    intake::{Document, DocumentReader},
    ownership::{ContextGuard, OperationOutput},
    progress::{ItemCursor, ProgressHub},
    streaming::StreamFinal,
    *,
};
use oncl_api::dto::{
    BatchItemOutcome, BatchItemRecord, BatchStatus, BatchStop as StopRecord, BatchStopKind,
    InspectTarget, JwsFormat, SourceIdentity,
};
use oncl_core::{
    SignProfile,
    batch::{
        BatchApproval, BatchError, BatchEvent, BatchItem, BatchItemResult, BatchOperation,
        BatchOutcome, BatchOutput, BatchReport, BatchStop, CapturedBatch, CompletedOutput,
    },
    keys::{KeyId, KeyRequest, KeySelector},
};
use oncl_pki::{io::Source, io::StagedArtifact};
use std::{cell::RefCell, io::Cursor};

/// Metadata reserved per item (record + terminal copy) before any private use, so a
/// later quota stop cannot starve the mandatory terminal record.
const RECORD_BYTES: u64 = 512;

pub(super) struct Run<'r> {
    pub root: &'r Arc<OperationOutput>,
    pub store: &'r Arc<ArtifactStore>,
    pub hub: &'r Arc<ProgressHub>,
    pub recheck: &'r (dyn Fn(&OperationMetadata) -> Result<(), ApiError> + Send + Sync),
}
/// Refused: nothing has run (typed HTTP error before any header). Abort: failure after
/// approval that cannot be reported in a terminal record (clean transport abort).
enum Fail {
    Refused(ApiError),
    Abort(ProcessingError),
}
fn refused(root: &OperationOutput, error: OperationError) -> Fail {
    Fail::Refused(match error {
        OperationError::Processing(error) => processing_error(root.failure().recover(error)),
        error => operation_failure(&error),
    })
}
fn batch_refused(root: &OperationOutput, error: BatchError) -> Fail {
    match error {
        BatchError::ConsentMismatch => {
            Fail::Refused(ApiError::not_applied(ErrorCode::PermissionDenied))
        }
        BatchError::Operation(error) => refused(root, error),
    }
}
/// Owned per-item inputs, in the operation's declared order.
#[derive(Default)]
struct Aux {
    evidence: Option<dispatch::Evidence>,
    certificate: Option<oncl_pki::cert::Certificate>,
    /// JOSE payloads: the SDK borrows bounded slices of the exact bytes.
    blobs: Vec<Vec<u8>>,
    _reservations: Vec<ResourceReservation>,
    selector: Option<KeySelector>,
    jwt_policy: Option<oncl_core::jose::JwtValidationPolicy>,
    /// Source lengths the host expects the captured plan to bind.
    source_bytes: Vec<u64>,
}
/// OCSP and CRL evidence slices of one item.
type Status<'a> = (Vec<&'a [u8]>, Vec<&'a [u8]>);
/// The composition the host authorized, built from the typed request itself.
struct Expected<'a> {
    id: &'a str,
    action: Action,
    keys: Vec<KeyId>,
    profile: Option<SignProfile>,
    sources: Vec<u64>,
}
fn gather(
    item: &oncl_api::dto::ItemMetadata,
    env: &mut dispatch::Env<'_>,
    ctx: &mut OperationContext,
) -> Result<(Vec<Document>, Aux, Option<StagedArtifact>), OperationError> {
    use oncl_core::jose::{MAX_CLAIMS_BYTES, MAX_PAYLOAD_BYTES};
    let mut docs = Vec::new();
    let mut aux = Aux::default();
    let take = |env: &mut dispatch::Env<'_>,
                docs: &mut Vec<Document>,
                aux: &mut Aux,
                name: &str|
     -> Result<(), OperationError> {
        let document = env.documents.take(name)?;
        aux.source_bytes.push(document.len());
        docs.push(document);
        Ok(())
    };
    let blob = |env: &mut dispatch::Env<'_>,
                ctx: &mut OperationContext,
                aux: &mut Aux,
                name: &str,
                maximum: usize|
     -> Result<(), OperationError> {
        let mut document = env.documents.take(name)?;
        let (bytes, reservation) = dispatch::read_bytes(&mut document, ctx, maximum)?;
        aux.source_bytes.push(bytes.len() as u64);
        aux.blobs.push(bytes);
        aux._reservations.push(reservation);
        Ok(())
    };
    match &item.operation {
        Operation::Hash { input, .. }
        | Operation::Extract { input }
        | Operation::Stamp { input } => take(env, &mut docs, &mut aux, input)?,
        Operation::Verify {
            input, detached, ..
        } => {
            take(env, &mut docs, &mut aux, input)?;
            if let Some(name) = detached {
                take(env, &mut docs, &mut aux, name)?;
            }
        }
        Operation::VerifyStamp { token, data, .. } => {
            take(env, &mut docs, &mut aux, token)?;
            if let Some(name) = data {
                take(env, &mut docs, &mut aux, name)?;
            }
        }
        Operation::Sign {
            input,
            detached,
            evidence,
            ..
        }
        | Operation::Extend {
            input,
            detached,
            evidence,
            ..
        } => {
            aux.evidence = Some(dispatch::load_evidence(env, evidence, ctx)?);
            take(env, &mut docs, &mut aux, input)?;
            if let Some(name) = detached {
                take(env, &mut docs, &mut aux, name)?;
            }
        }
        Operation::Inspect { target } => match target {
            InspectTarget::Certificate { input } | InspectTarget::Cms { input } => {
                docs.push(env.documents.take(input)?);
            }
            InspectTarget::Named { name } => {
                aux.selector = Some(KeySelector::named(
                    KeyId::new(name).map_err(|_| ProcessingError::InvalidInput("key name"))?,
                ));
            }
            InspectTarget::Container { .. } => {}
        },
        Operation::JwsSign { input, .. } => {
            blob(env, ctx, &mut aux, input, MAX_PAYLOAD_BYTES)?;
        }
        Operation::JwsAdd {
            input,
            detached,
            certificate,
            ..
        }
        | Operation::JwsVerify {
            input,
            detached,
            certificate,
            ..
        } => {
            aux.certificate = dispatch::certificate(env, certificate.clone(), ctx)?;
            blob(env, ctx, &mut aux, input, MAX_PAYLOAD_BYTES * 2)?;
            if let Some(name) = detached {
                blob(env, ctx, &mut aux, name, MAX_PAYLOAD_BYTES)?;
            }
        }
        Operation::JwtEncode { input, .. } | Operation::JwtDecode { input } => {
            blob(env, ctx, &mut aux, input, MAX_CLAIMS_BYTES)?;
        }
        Operation::JwtVerify { input, certificate } => {
            aux.certificate = dispatch::certificate(env, certificate.clone(), ctx)?;
            blob(env, ctx, &mut aux, input, MAX_CLAIMS_BYTES)?;
            let mut policy = oncl_core::jose::JwtValidationPolicy::new(
                time::OffsetDateTime::now_utc().unix_timestamp(),
            );
            policy.expected_issuer = env.host.jwt_issuer.clone();
            policy.expected_audience = env.host.jwt_audience.clone();
            aux.jwt_policy = Some(policy);
        }
        Operation::Plugin { .. } => {
            return Err(ProcessingError::InvalidInput("plugin items are not batchable").into());
        }
    }
    let stage = if dispatch::has_output(&item.operation) {
        Some(dispatch::staged_output(env, ctx)?)
    } else {
        None
    };
    Ok((docs, aux, stage))
}

fn owned_output<'a>(stage: &mut Option<StagedArtifact>) -> Result<BatchOutput<'a>, Fail> {
    stage
        .take()
        .map(BatchOutput::OwnedStaged)
        .ok_or(Fail::Refused(ApiError::not_applied(
            ErrorCode::MissingTemporaryStore,
        )))
}
/// The explicit host approval step. Produces the SDK `BatchApproval` only if the
/// captured plan is exactly the composition the host authorized; never from a payload
/// flag. A plan that differs in count/order, ids, actions, profile, resolved keys or
/// captured source sizes is refused before any private key is applied.
fn approve(
    plan: &CapturedBatch<'_>,
    expected: &[Expected<'_>],
    ctx: &OperationContext,
) -> Result<BatchApproval, ApiError> {
    let denied = || ApiError::not_applied(ErrorCode::PermissionDenied);
    if plan.items().len() != expected.len() {
        return Err(denied());
    }
    for (view, want) in plan.items().zip(expected) {
        // An item-local capture failure never runs (it is reported as `failed` and never
        // reaches a key): it carries neither resolved keys nor source facts.
        let keys_match = view.capture_error.is_some()
            || (view.keys.len() == want.keys.len()
                && view.keys.iter().zip(&want.keys).all(|(b, k)| b.key() == k));
        let sources_match = view.capture_error.is_some()
            || (view.sources.len() == want.sources.len()
                && view
                    .sources
                    .iter()
                    .zip(&want.sources)
                    .all(|(s, bytes)| s.bytes() == *bytes));
        if view.id != want.id
            || view.action != want.action
            || view.signing_profile != want.profile
            || !keys_match
            || !sources_match
        {
            return Err(denied());
        }
    }
    plan.authorize(ctx).map_err(|error| match error {
        BatchError::ConsentMismatch => denied(),
        BatchError::Operation(error) => operation_failure(&error),
    })
}

#[derive(Default)]
struct RunState {
    records: Vec<BatchItemRecord>,
    artifacts: Vec<(String, FinishedArtifact)>,
    /// Content-ID of the finished output of an item, by manifest index.
    artifact_of: Vec<Option<String>>,
    reservations: Vec<ResourceReservation>,
    /// Released before the terminal record is serialized.
    terminal: Vec<ResourceReservation>,
    fault: Option<ProcessingError>,
}
fn project(
    operation: &Operation,
    report: &BatchReport,
    result: &BatchItemResult,
    artifact: Option<String>,
) -> Result<results::Projection, ProcessingError> {
    let mismatch = || ProcessingError::InvalidInput("batch report does not match its item");
    Ok(match (report, operation) {
        (BatchReport::Hash(report), Operation::Hash { algorithm, .. }) => results::hash(
            *algorithm,
            report,
            result.sources().first().map_or(0, |s| s.bytes()),
        ),
        (BatchReport::Verify(report), Operation::Verify { profile, .. }) => {
            results::verification(*profile, report)?
        }
        (BatchReport::Extract(report), Operation::Extract { .. }) => {
            results::extraction(artifact, report)
        }
        (BatchReport::Sign(report), Operation::Sign { profile, .. }) => {
            results::signing(*profile, artifact, report)?
        }
        (BatchReport::Extend(report), Operation::Extend { profile, .. }) => {
            results::extension(*profile, artifact, report)?
        }
        (BatchReport::Inspect(report), Operation::Inspect { target }) => results::inspection(
            match target {
                InspectTarget::Certificate { .. } => "certificate",
                InspectTarget::Cms { .. } => "cms",
                InspectTarget::Container { .. } => "container",
                InspectTarget::Named { .. } => "named_key",
            },
            report,
        )?,
        (BatchReport::Stamp(report), Operation::Stamp { .. }) => {
            results::stamping(artifact, report)
        }
        (BatchReport::Stamp(report), Operation::VerifyStamp { .. }) => {
            results::stamp_verification(report)
        }
        (
            BatchReport::JoseWrite(report),
            Operation::JwsSign { serialization, .. } | Operation::JwsAdd { serialization, .. },
        ) => results::jose_written(*serialization, artifact, report),
        (BatchReport::JoseWrite(report), Operation::JwtEncode { .. }) => {
            results::jose_written(JwsFormat::Compact, artifact, report)
        }
        (BatchReport::JwsVerify(report), Operation::JwsVerify { .. }) => {
            results::jws_verification(report)
        }
        (BatchReport::JwtDecode(report), Operation::JwtDecode { .. }) => {
            results::jwt_decoded(report)
        }
        (BatchReport::JwtVerify(report), Operation::JwtVerify { .. }) => {
            results::jwt_verification(report)
        }
        _ => return Err(mismatch()),
    })
}
fn record(
    root: &OperationOutput,
    item: &oncl_api::dto::ItemMetadata,
    index: usize,
    result: &BatchItemResult,
    artifact: Option<String>,
    state: &mut RunState,
) -> Result<BatchItemRecord, ProcessingError> {
    let sources = result
        .sources()
        .iter()
        .map(|s| SourceIdentity {
            sha256: crate::auth::encode(s.sha256().as_bytes()),
            bytes: s.bytes(),
        })
        .collect();
    let applied = api_applied(result.applied_state());
    let (outcome, verdict, error, projected) = match result.outcome() {
        BatchOutcome::Completed(report) => {
            let (projected, bytes) = project(&item.operation, report, result, artifact)?;
            state
                .reservations
                .push(root.scope().reserve_metadata(bytes)?);
            state
                .terminal
                .push(root.scope().reserve_metadata(bytes + 512)?);
            (
                BatchItemOutcome::Completed,
                projected.verdict(),
                None,
                Some(projected),
            )
        }
        BatchOutcome::Failed(error) => (
            BatchItemOutcome::Failed,
            None,
            Some(operation_failure(error)),
            None,
        ),
        BatchOutcome::NotRun => (BatchItemOutcome::NotRun, None, None, None),
    };
    {
        use crate::telemetry::{ItemResult, ItemTimer, Observer, operation_kind};
        let observer = Observer::worker();
        if observer.enabled() {
            let (kind, family) = operation_kind(&item.operation);
            match (&outcome, &error) {
                (BatchItemOutcome::Completed, _) => {
                    observer.item_end(ItemTimer::none(), kind, family, ItemResult::Ok(applied));
                }
                (BatchItemOutcome::Failed, Some(failure)) => observer.item_end(
                    ItemTimer::none(),
                    kind,
                    family,
                    ItemResult::Failed(failure.code, failure.applied),
                ),
                _ => {}
            }
        }
    }
    Ok(BatchItemRecord {
        item_id: item.id.clone(),
        index,
        outcome,
        applied,
        verdict,
        error,
        result: projected,
        sources,
    })
}

pub(super) fn execute(
    run: Run<'_>,
    guard: &mut ContextGuard,
    metadata: OperationMetadata,
    env: &mut dispatch::Env<'_>,
    ready: &mut dyn FnMut(Result<(), ApiError>),
) -> Result<StreamFinal, ProcessingError> {
    match drive(&run, guard, &metadata, env, &mut || ready(Ok(()))) {
        Ok(done) => Ok(done),
        Err(Fail::Refused(api)) => {
            ready(Err(api));
            Err(ProcessingError::InvalidInput(
                "batch refused before any item",
            ))
        }
        Err(Fail::Abort(error)) => Err(error),
    }
}

fn drive(
    run: &Run<'_>,
    guard: &mut ContextGuard,
    metadata: &OperationMetadata,
    env: &mut dispatch::Env<'_>,
    approved: &mut dyn FnMut(),
) -> Result<StreamFinal, Fail> {
    let root = run.root;
    let total = metadata.items.len();
    let refuse = |error: OperationError| refused(root, error);
    let processing = |error: ProcessingError| refused(root, error.into());
    let _record_budget = root
        .scope()
        .reserve_metadata(total as u64 * RECORD_BYTES)
        .map_err(processing)?;
    let terminal_budget = root
        .scope()
        .reserve_metadata(total as u64 * RECORD_BYTES)
        .map_err(processing)?;
    // Stage A: owned inputs, output stages and bounded evidence, in manifest order.
    let mut docs: Vec<Vec<Document>> = Vec::with_capacity(total);
    let mut aux: Vec<Aux> = Vec::with_capacity(total);
    let mut stages: Vec<Option<StagedArtifact>> = Vec::with_capacity(total);
    for item in &metadata.items {
        let (d, a, s) = gather(item, env, guard.context()).map_err(refuse)?;
        docs.push(d);
        aux.push(a);
        stages.push(s);
    }
    let secrets = env.secrets;
    let selectors = env.selectors;
    let engine = env.engine;
    let host = env.host;
    // Stage B: borrowing views.
    let slices: Vec<Status<'_>> = aux
        .iter()
        .map(|a| a.evidence.as_ref().map(|e| e.slices()).unwrap_or_default())
        .collect();
    let named: Vec<Option<KeyRequest<'_>>> = aux
        .iter()
        .map(|a| a.selector.as_ref().map(|s| KeyRequest::new(s, None)))
        .collect();
    let mut cursors: Vec<Option<Cursor<&[u8]>>> = Vec::with_capacity(total);
    for item in &metadata.items {
        cursors.push(match &item.operation {
            Operation::Inspect {
                target: InspectTarget::Container { container, .. },
            } => Some(Cursor::new(secrets.bytes(container).map_err(processing)?)),
            _ => None,
        });
    }
    let mut readers: Vec<Vec<DocumentReader<'_>>> = Vec::with_capacity(total);
    for list in docs.iter_mut() {
        let mut row = Vec::with_capacity(list.len());
        for document in list.iter_mut() {
            row.push(
                document
                    .reader(guard.context().resources())
                    .map_err(processing)?,
            );
        }
        readers.push(row);
    }
    let limits = dispatch::evidence_limits(guard.context().resources().limits());
    // Stage C: typed SDK items, with the composition the host authorizes.
    let mut items: Vec<BatchItem<'_>> = Vec::with_capacity(total);
    let mut expected: Vec<Expected<'_>> = Vec::with_capacity(total);
    for (((index, item), row), cursor) in metadata
        .items
        .iter()
        .enumerate()
        .zip(readers.iter_mut())
        .zip(cursors.iter_mut())
    {
        let a = &aux[index];
        let invalid = |what: &'static str| refuse(ProcessingError::InvalidInput(what).into());
        let mut rows = row.iter_mut();
        let mut next_source = || rows.next().map(DocumentReader::source);
        let mut want = Expected {
            id: &item.id,
            action: dispatch::action(&item.operation),
            keys: Vec::new(),
            profile: None,
            sources: a.source_bytes.clone(),
        };
        let selectors_of = |id: &str| -> Result<&[KeySelector], Fail> {
            selectors
                .get(id)
                .map(Vec::as_slice)
                .ok_or_else(|| invalid("unresolved signing keys"))
        };
        let operation = match &item.operation {
            Operation::Hash { algorithm, .. } => BatchOperation::Hash {
                algorithm: super::algorithm(*algorithm),
                input: next_source().ok_or_else(|| invalid("missing source"))?,
            },
            Operation::Verify { profile, soap, .. } => BatchOperation::Verify {
                request: dispatch::verify_request(*profile, *soap, limits),
                input: next_source().ok_or_else(|| invalid("missing source"))?,
                detached: next_source(),
            },
            Operation::Extract { .. } => BatchOperation::Extract {
                input: next_source().ok_or_else(|| invalid("missing source"))?,
                output: owned_output(&mut stages[index])?,
            },
            Operation::Sign {
                profile,
                mode,
                attached,
                target,
                parent,
                signature_id,
                soap,
                body_id,
                element,
                xpath_parent,
                signature_method,
                digest_method,
                keys,
                ..
            } => {
                let selectors = selectors_of(&item.id)?;
                want.keys = selectors.iter().map(KeySelector::key_id).collect();
                let requests_for_keys =
                    dispatch::key_requests(keys, selectors, secrets).map_err(refuse)?;
                let (ocsp, crls) = &slices[index];
                let material = oncl_pki::cms::ades::ValidationMaterial {
                    certificates: a
                        .evidence
                        .as_ref()
                        .map_or(&[][..], |e| e.certificates.as_slice()),
                    ocsp,
                    crls,
                };
                let input = next_source().ok_or_else(|| invalid("missing source"))?;
                let spec = requests::SignSpec {
                    profile: *profile,
                    mode: *mode,
                    attached: *attached,
                    target: target.as_deref(),
                    parent: parent.as_deref(),
                    signature_id: signature_id.as_deref(),
                    soap: *soap,
                    body_id: body_id.as_deref(),
                    element: element.as_deref(),
                    xpath_parent: xpath_parent.as_deref(),
                    signature_method: signature_method.as_deref(),
                    digest_method: digest_method.as_deref(),
                };
                let request = requests::sign_request(
                    &spec,
                    requests_for_keys,
                    next_source(),
                    material,
                    limits,
                    host.tsa.as_ref(),
                )
                .map_err(refuse)?;
                want.profile = Some(request.profile());
                BatchOperation::Sign {
                    request,
                    input,
                    output: owned_output(&mut stages[index])?,
                }
            }
            Operation::Extend { profile, .. } => {
                let (ocsp, crls) = &slices[index];
                let material = oncl_pki::cms::ades::ValidationMaterial {
                    certificates: a
                        .evidence
                        .as_ref()
                        .map_or(&[][..], |e| e.certificates.as_slice()),
                    ocsp,
                    crls,
                };
                let input = next_source().ok_or_else(|| invalid("missing source"))?;
                let request = requests::extend_request(*profile, next_source(), material, limits)
                    .map_err(refuse)?;
                BatchOperation::Extend {
                    request,
                    input,
                    output: owned_output(&mut stages[index])?,
                }
            }
            Operation::Inspect { target } => {
                want.sources.clear();
                match target {
                    InspectTarget::Certificate { .. } => BatchOperation::Inspect {
                        request: oncl_core::InspectRequest::certificate(),
                        input: Some(next_source().ok_or_else(|| invalid("missing source"))?),
                    },
                    InspectTarget::Cms { .. } => BatchOperation::Inspect {
                        request: oncl_core::InspectRequest::cms_metadata(),
                        input: Some(next_source().ok_or_else(|| invalid("missing source"))?),
                    },
                    InspectTarget::Named { .. } => BatchOperation::Inspect {
                        request: oncl_core::InspectRequest::named_key(
                            named[index].as_ref().ok_or_else(|| invalid("named key"))?,
                        ),
                        input: None,
                    },
                    InspectTarget::Container { password, .. } => {
                        let password = password
                            .as_deref()
                            .map(|name| secrets.text(name))
                            .transpose()
                            .map_err(processing)?;
                        let cursor = cursor.as_mut().ok_or_else(|| invalid("container secret"))?;
                        let length = cursor.get_ref().len() as u64;
                        BatchOperation::Inspect {
                            request: oncl_core::InspectRequest::container(password),
                            input: Some(Source::sequential(cursor, Some(length))),
                        }
                    }
                }
            }
            Operation::Stamp { .. } => BatchOperation::Stamp {
                request: oncl_core::StampRequest::new(
                    host.tsa
                        .clone()
                        .ok_or_else(|| refuse(OperationError::MissingCadesConfiguration))?,
                ),
                input: next_source().ok_or_else(|| invalid("missing source"))?,
                output: owned_output(&mut stages[index])?,
            },
            Operation::VerifyStamp {
                algorithm: expected_algorithm,
                max_age_seconds,
                ..
            } => {
                let mut request = oncl_core::StampVerifyRequest::new();
                if let Some(algorithm) = expected_algorithm {
                    request = request.with_algorithm(super::algorithm(*algorithm));
                }
                if let Some(seconds) = max_age_seconds {
                    request = request.with_maximum_age(std::time::Duration::from_secs(*seconds));
                }
                BatchOperation::VerifyStamp {
                    request,
                    token: next_source().ok_or_else(|| invalid("missing source"))?,
                    data: next_source(),
                }
            }
            Operation::JwsSign {
                serialization,
                detached,
                keys,
                ..
            } => {
                let selectors = selectors_of(&item.id)?;
                want.keys = selectors.iter().map(KeySelector::key_id).collect();
                BatchOperation::Jose(oncl_core::batch::BatchJoseOperation::Create {
                    profile: dispatch::jose_profile(*serialization, *detached),
                    keys: dispatch::key_requests(keys, selectors, secrets).map_err(refuse)?,
                    payload: &a.blobs[0],
                    output: owned_output(&mut stages[index])?,
                })
            }
            Operation::JwsAdd {
                serialization,
                keys,
                ..
            } => {
                let selectors = selectors_of(&item.id)?;
                want.keys = selectors.iter().map(KeySelector::key_id).collect();
                let mut request = oncl_core::jose::JwsVerifyRequest::new(dispatch::jose_profile(
                    *serialization,
                    a.blobs.len() > 1,
                ));
                request.certificate = a.certificate.as_ref();
                BatchOperation::Jose(oncl_core::batch::BatchJoseOperation::Add {
                    request,
                    keys: dispatch::key_requests(keys, selectors, secrets).map_err(refuse)?,
                    input: &a.blobs[0],
                    detached: a.blobs.get(1).map(Vec::as_slice),
                    output: owned_output(&mut stages[index])?,
                })
            }
            Operation::JwsVerify { serialization, .. } => {
                let mut request = oncl_core::jose::JwsVerifyRequest::new(dispatch::jose_profile(
                    *serialization,
                    a.blobs.len() > 1,
                ));
                request.certificate = a.certificate.as_ref();
                BatchOperation::Jose(oncl_core::batch::BatchJoseOperation::Verify {
                    request,
                    input: &a.blobs[0],
                    detached: a.blobs.get(1).map(Vec::as_slice),
                })
            }
            Operation::JwtEncode { key, .. } => {
                let selectors = selectors_of(&item.id)?;
                want.keys = selectors.iter().map(KeySelector::key_id).collect();
                let mut keys =
                    dispatch::key_requests(std::slice::from_ref(key), selectors, secrets)
                        .map_err(refuse)?;
                BatchOperation::Jose(oncl_core::batch::BatchJoseOperation::JwtEncode {
                    key: keys.remove(0),
                    claims: &a.blobs[0],
                    output: owned_output(&mut stages[index])?,
                })
            }
            Operation::JwtDecode { .. } => {
                BatchOperation::Jose(oncl_core::batch::BatchJoseOperation::JwtDecode {
                    input: &a.blobs[0],
                })
            }
            Operation::JwtVerify { .. } => {
                BatchOperation::Jose(oncl_core::batch::BatchJoseOperation::JwtVerify {
                    certificate: a.certificate.as_ref(),
                    input: &a.blobs[0],
                    policy: a.jwt_policy.as_ref().ok_or_else(|| invalid("jwt policy"))?,
                })
            }
            Operation::Plugin { .. } => return Err(invalid("plugin items are not batchable")),
        };
        items.push(BatchItem::new(&item.id, operation));
        expected.push(want);
    }
    // Capture is read-only with respect to private keys: it pins sources and resolves
    // each key lease/certificate. The host decides afterwards, from the CAPTURED plan.
    let plan = engine
        .capture_batch(items, guard.context())
        .map_err(|error| batch_refused(root, error))?;
    // Authority may have changed (revocation, right removal) while the body was
    // taken and the sources captured: decide again, as late as possible.
    (run.recheck)(metadata).map_err(Fail::Refused)?;
    let approval = approve(&plan, &expected, guard.context()).map_err(Fail::Refused)?;
    approved();
    // Stage D: sequential execution under the original context. Nothing below can
    // change the response status: failures are per-item records or a clean abort.
    let hub = run.hub;
    hub.publish_items(ItemCursor {
        total: total as u32,
        finished: 0,
        current: None,
    });
    let state = RefCell::new(RunState {
        records: Vec::with_capacity(total),
        artifact_of: vec![None; total],
        ..RunState::default()
    });
    let summary = engine.run_batch_with_outputs(
        plan,
        approval,
        guard.context(),
        |event| match event {
            BatchEvent::Started { .. } | BatchEvent::Finished { .. } => {}
            BatchEvent::ItemStarted { index, .. } => {
                let finished = state.borrow().records.len() as u32;
                hub.publish_items(ItemCursor {
                    total: total as u32,
                    finished,
                    current: Some(index as u32),
                });
            }
            BatchEvent::ItemFinished { result, .. } => {
                let mut state = state.borrow_mut();
                let index = state.records.len();
                let artifact = state.artifact_of.get(index).cloned().flatten();
                match record(
                    root,
                    &metadata.items[index],
                    index,
                    result,
                    artifact,
                    &mut state,
                ) {
                    Ok(record) => state.records.push(record),
                    Err(error) => {
                        // The mandatory terminal record can no longer be completed
                        // honestly: remember the first cause and abort cleanly.
                        if state.fault.is_none() {
                            state.fault = Some(error);
                        }
                        let placeholder_index = state.records.len();
                        state.records.push(BatchItemRecord {
                            item_id: metadata.items[placeholder_index].id.clone(),
                            index: placeholder_index,
                            outcome: BatchItemOutcome::Failed,
                            applied: api_applied(result.applied_state()),
                            verdict: None,
                            error: None,
                            result: None,
                            sources: Vec::new(),
                        });
                    }
                }
                let finished = state.records.len() as u32;
                hub.publish_items(ItemCursor {
                    total: total as u32,
                    finished,
                    current: None,
                });
            }
        },
        |index, _id, _report, completed: CompletedOutput| {
            let length = completed.len();
            let mut writer = ArtifactWriter::open(run.store.clone(), root.clone())?;
            let copied = completed.copy_to(&mut writer)?;
            if copied != length {
                return Err(ProcessingError::InvalidInput("staged output length changed").into());
            }
            let artifact = writer.finish(length)?;
            let mut state = state.borrow_mut();
            let id = format!("artifact-{}", state.artifacts.len());
            state.artifacts.push((id.clone(), artifact));
            state.artifact_of[index] = Some(id);
            Ok(())
        },
    );
    let summary = summary.map_err(|_| {
        Fail::Abort(ProcessingError::InvalidInput(
            "approved batch could not start",
        ))
    })?;
    let mut state = state.into_inner();
    if let Some(error) = state.fault.take() {
        return Err(Fail::Abort(error));
    }
    if state.records.len() != total {
        return Err(Fail::Abort(ProcessingError::InvalidInput(
            "terminal record incomplete",
        )));
    }
    let stop = summary.stop.as_ref().map(|stop| match stop {
        BatchStop::Control(error) => StopRecord {
            kind: BatchStopKind::Control,
            code: api_code(error.code()),
            item_index: None,
            applied: api_applied(error.applied_state()),
        },
        BatchStop::Item {
            index,
            code,
            applied,
        } => StopRecord {
            kind: BatchStopKind::Item,
            code: api_code(*code),
            item_index: Some(*index),
            applied: api_applied(*applied),
        },
    });
    // The terminal copy was reserved before any private use; hand that capacity to
    // the serializer now.
    drop(state.terminal);
    drop(terminal_budget);
    let event = root
        .json_event(&ResponseEvent::BatchFinal {
            operation_id: root.id().get(),
            status: if summary.completed == summary.total {
                BatchStatus::Completed
            } else {
                BatchStatus::Partial
            },
            attempted: summary.attempted,
            completed: summary.completed,
            total: summary.total,
            stop,
            items: state.records,
            error: None,
        })
        .map_err(Fail::Abort)?;
    Ok(StreamFinal {
        event,
        artifacts: state.artifacts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::Cancellation;
    use oncl_core::{EngineServices, ExecutionGrant, OperationPolicy};
    use oncl_pki::{io::TemporaryStore, key::HashAlg, resource::ResourceLimits};

    fn engine(directory: &std::path::Path) -> Engine {
        Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_temporary_store(TemporaryStore::new(directory).unwrap()),
        )
        .unwrap()
    }
    fn context(engine: &Engine) -> OperationContext {
        engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Cancellation::new()),
            )
            .unwrap()
    }
    fn expected(ids: &[&'static str]) -> Vec<Expected<'static>> {
        ids.iter()
            .map(|id| Expected {
                id,
                action: Action::Hash,
                keys: Vec::new(),
                profile: None,
                sources: vec![3],
            })
            .collect()
    }
    fn capture<'a>(
        engine: &Engine,
        ctx: &mut OperationContext,
        sources: &'a mut [&'a [u8]],
        ids: &[&'a str],
    ) -> CapturedBatch<'a> {
        let items: Vec<_> = ids
            .iter()
            .zip(sources.iter_mut())
            .map(|(id, bytes)| {
                BatchItem::new(
                    id,
                    BatchOperation::Hash {
                        algorithm: HashAlg::Sha256,
                        input: Source::sequential(bytes, Some(3)),
                    },
                )
            })
            .collect();
        engine.capture_batch(items, ctx).map_err(|_| ()).unwrap()
    }

    #[test]
    fn approval_is_produced_only_for_exactly_the_authorized_composition() {
        let directory = tempfile::tempdir().unwrap();
        let engine = engine(directory.path());
        {
            let mut ctx = context(&engine);
            let mut data: [&[u8]; 2] = [b"abc", b"abc"];
            let plan = capture(&engine, &mut ctx, &mut data, &["a", "b"]);
            assert!(approve(&plan, &expected(&["a", "b"]), &ctx).is_ok());
        }
        // Every deviation of the authorized composition is refused with 403/NotApplied.
        let refused = |tampered: Vec<Expected<'static>>| {
            let data: &mut [&[u8]] = &mut [b"abc", b"abc"];
            let mut ctx = context(&engine);
            let plan = capture(&engine, &mut ctx, data, &["a", "b"]);
            let error = approve(&plan, &tampered, &ctx).err().expect("refused");
            assert_eq!(error.code, ErrorCode::PermissionDenied);
            assert_eq!(error.applied, oncl_api::error::AppliedState::NotApplied);
        };
        refused(expected(&["b", "a"])); // order
        refused(expected(&["a", "c"])); // id
        refused(expected(&["a"])); // fewer items
        refused(expected(&["a", "b", "c"])); // more items
        let mut action = expected(&["a", "b"]);
        action[1].action = Action::Sign;
        refused(action);
        let mut source = expected(&["a", "b"]);
        source[0].sources = vec![4]; // different captured source length
        refused(source);
        let mut keyed = expected(&["a", "b"]);
        keyed[1].keys = vec![KeyId::new("k").unwrap()]; // a key the plan never bound
        refused(keyed);
        let mut profile = expected(&["a", "b"]);
        profile[0].profile = Some(SignProfile::Cms); // a signing profile the plan lacks
        refused(profile);
    }

    #[test]
    fn an_approval_cannot_run_a_different_captured_plan() {
        let directory = tempfile::tempdir().unwrap();
        let engine = engine(directory.path());
        let mut ctx = context(&engine);
        let mut first: [&[u8]; 1] = [b"abc"];
        let mut second: [&[u8]; 2] = [b"abc", b"abc"];
        let plan_a = capture(&engine, &mut ctx, &mut first, &["a"]);
        let plan_b = capture(&engine, &mut ctx, &mut second, &["a", "b"]);
        let approval_a = approve(&plan_a, &expected(&["a"]), &ctx).unwrap();
        let outcome = engine.run_batch(plan_b, approval_a, &mut ctx, |_| {});
        assert!(
            matches!(outcome, Err(BatchError::ConsentMismatch)),
            "a changed composition cannot reuse an approval"
        );
        // And the plan the approval was made for still runs with its own approval.
        let approval = approve(&plan_a, &expected(&["a"]), &ctx).unwrap();
        let summary = engine
            .run_batch(plan_a, approval, &mut ctx, |_| {})
            .unwrap();
        assert_eq!(summary.completed, 1);
    }
}
