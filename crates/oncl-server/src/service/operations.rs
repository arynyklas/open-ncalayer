pub(crate) mod artifact;
mod dispatch;
pub(super) mod intake;
mod ownership;
pub(super) mod progress;
mod streaming;

use super::*;
use crate::audit::AuditHealth;
use oncl_api::dto::{
    FinalStatus, HashAlgorithm, ItemResult, Operation, OperationMetadata, OperationResult,
    PartRole, ResponseEvent,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const JSON_BYTES: u64 = 65_536;
/// Immutable operator policy shared by every operation (never client-supplied).
pub(crate) struct HostPolicy {
    pub tsa: Option<oncl_pki::tsp::TsaSpec>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmallRequest {
    metadata: OperationMetadata,
    #[serde(deserialize_with = "unique_documents")]
    documents: BTreeMap<String, String>,
}
fn unique_documents<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Documents;
    impl<'de> serde::de::Visitor<'de> for Documents {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique text document names")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, String>()? {
                if result.insert(name, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate document"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Documents)
}
fn invalid_request() -> ApiError {
    ApiError::not_applied(ErrorCode::InvalidRequest)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn validate_metadata(metadata: &OperationMetadata) -> Result<(), ApiError> {
    if metadata.items.is_empty() || metadata.items.len() > 1024 || metadata.parts.len() > 2048 {
        return Err(invalid_request());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut used = BTreeSet::new();
    for item in &metadata.items {
        if !identifier(&item.id) || !ids.insert(item.id.as_str()) {
            return Err(invalid_request());
        }
        let documents = dispatch::inputs(&item.operation).map(|n| (n, PartRole::Document));
        let secrets = dispatch::secret_refs(&item.operation)
            .into_iter()
            .map(|(n, _)| (n, PartRole::Secret));
        for (input, role) in documents.chain(secrets) {
            if !used.insert(input) {
                return Err(invalid_request());
            }
            let part = metadata
                .parts
                .iter()
                .find(|p| p.name == input)
                .ok_or_else(invalid_request)?;
            if part.item_id != item.id || part.role != role {
                return Err(invalid_request());
            }
        }
    }
    let mut seen_document = false;
    for part in &metadata.parts {
        if !identifier(&part.name) || !names.insert(part.name.as_str()) {
            return Err(invalid_request());
        }
        if !used.contains(part.name.as_str()) {
            return Err(invalid_request());
        }
        // Secrets precede documents so every key is authorized before any
        // document byte is consumed.
        match part.role {
            PartRole::Document => seen_document = true,
            PartRole::Secret if seen_document => return Err(invalid_request()),
            PartRole::Secret => {}
        }
    }
    Ok(())
}
fn algorithm(value: HashAlgorithm) -> HashAlg {
    match value {
        HashAlgorithm::Sha1 => HashAlg::Sha1,
        HashAlgorithm::Sha256 => HashAlg::Sha256,
        HashAlgorithm::Sha512 => HashAlg::Sha512,
        HashAlgorithm::Gost34311 => HashAlg::Gost34311,
        HashAlgorithm::Streebog256 => HashAlg::Streebog256,
        HashAlgorithm::Streebog512 => HashAlg::Streebog512,
    }
}
pub(super) fn evidence_limits(
    limits: &oncl_pki::resource::ResourceLimits,
) -> oncl_pki::evidence::EvidenceLimits {
    dispatch::evidence_limits(limits)
}
async fn await_worker<T>(
    work: crate::executor::WorkHandle<T>,
    deadline: Deadline,
    failure: &intake::Failure,
) -> Result<T, ApiError> {
    tokio::time::timeout(deadline.remaining(), work.wait())
        .await
        .map_err(|_| processing_error(failure.recover(ProcessingError::DeadlineExceeded)))?
        .map_err(|error| processing_error(failure.recover(error)))
}
impl ServiceHost {
    pub(super) fn dispatch_operations(
        &self,
        metadata: RequestMetadata,
        body: Body,
    ) -> ResponseFuture {
        let deadline = Deadline::after(Duration::from_millis(self.config.operation_timeout_ms))
            .map_err(processing_error);
        let cancel = Arc::new(Cancellation::new());
        let principal = self.principal(&metadata);
        let engine = self.engine.clone();
        let policy = self.policy.clone();
        let executor = self.executor.clone();
        let store = self.store.clone();
        let output_store = self.output_store.clone();
        let audit = self.audit.clone();
        let keys = self.keys.clone();
        let inline_enabled = self.config.inline_pkcs12;
        let host_policy = self.host_policy.clone();
        Box::pin(async move {
            let deadline = deadline?;
            let principal = principal?;
            let disconnect = Arc::new(CancelOnDrop(cancel.clone()));
            let (progress_hub, progress_receiver) = progress::ProgressHub::channel();
            let mut admission = engine
                .admit(Arc::new(InvocationControl {
                    cancel: cancel.clone(),
                    deadline,
                    progress: Some(progress_hub.clone()),
                }))
                .map_err(core_error)?;
            let header_bytes = metadata
                .headers
                .iter()
                .try_fold(0u64, |n, (k, v)| {
                    n.checked_add((k.as_str().len() + v.as_bytes().len() + 4) as u64)
                })
                .ok_or_else(invalid_request)?;
            let headers = admission
                .resources()
                .reserve_metadata(header_bytes)
                .map_err(processing_error)?;
            let mut prepared = intake::prepare(
                &metadata,
                body,
                &mut admission,
                deadline,
                cancel.clone(),
                &|m| dispatch::precheck(m, &policy, &principal, inline_enabled),
            )
            .await?;
            // Recheck the actual Principal generation and each resolved operation
            // after bounded metadata intake, before the first SDK dispatch.
            let mut actions = Vec::with_capacity(prepared.metadata.items.len());
            let mut private = false;
            for item in &prepared.metadata.items {
                let action = dispatch::action(&item.operation);
                // Key-bearing actions are authorized per exact key in resolve_keys.
                if !matches!(action, Action::Sign) {
                    policy
                        .authorize(&principal, action, None, None)
                        .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?;
                } else {
                    private = true;
                }
                actions.push(action);
            }
            let resolved = dispatch::resolve_keys(
                &prepared.metadata,
                &prepared.secrets,
                &policy,
                &principal,
                inline_enabled,
                admission.resources(),
            )?;
            if private && audit.health() != AuditHealth::Healthy {
                return Err(ApiError::not_applied(ErrorCode::AuditUnavailable));
            }
            let mut grant =
                oncl_core::ExecutionGrant::new(actions).with_keys(resolved.keys.clone());
            if prepared.metadata.items.iter().any(|i| {
                matches!(
                    i.operation,
                    Operation::Inspect {
                        target: oncl_api::dto::InspectTarget::Container { .. }
                    }
                )
            }) {
                // Exact host-granted aliases; a client cannot widen them.
                grant = grant.with_metadata_aliases(
                    policy
                        .metadata_aliases(&principal)
                        .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?,
                );
            }
            let failure = prepared.failure.clone();
            let mut ctx = engine
                .begin_admitted(admission, grant, OperationPolicy::strict_online())
                .map_err(core_error)?;
            // Durable audit binding: actor and key labels belong to this exact
            // original operation; no private key opens without it.
            let binding = if private {
                let mut labels: Vec<_> = keys
                    .labels()
                    .filter(|(id, _)| ctx.grant().allows_key(id))
                    .collect();
                labels.extend(
                    resolved
                        .inline
                        .keys()
                        .map(|id| (id.clone(), crate::keys::inline_label(id))),
                );
                Some(
                    audit
                        .bind(&ctx, principal.audit_label(), labels)
                        .map_err(|_| ApiError::not_applied(ErrorCode::AuditUnavailable))?,
                )
            } else {
                None
            };
            if prepared
                .metadata
                .items
                .iter()
                .any(|item| dispatch::has_output(&item.operation))
            {
                let output_store = output_store
                    .ok_or_else(|| ApiError::not_applied(ErrorCode::MissingTemporaryStore))?;
                prepared.reservations.push(headers);
                let delivery = ResponseDelivery {
                    deadline,
                    cancel,
                    control: ctx.resources().operation_control(),
                    _disconnect: disconnect,
                };
                return streaming::response(
                    streaming::StreamRuntime {
                        engine,
                        executor,
                        source_store: store,
                        output_store,
                        delivery,
                        progress: progress_hub,
                        receiver: progress_receiver,
                        failure,
                    },
                    ctx,
                    prepared,
                    streaming::PrivateState {
                        selectors: resolved.selectors,
                        reservations: resolved.reservations,
                        binding,
                        host: host_policy,
                    },
                )
                .await;
            }
            let runtime = tokio::runtime::Handle::current();
            let work = executor
                .submit(ctx, move |ctx| {
                    let _headers = headers;
                    let _intake = prepared.reservations;
                    let request = prepared.metadata;
                    let mut documents =
                        prepared
                            .payload
                            .capture(&request, store.as_ref(), ctx, runtime)?;
                    let mut results = Vec::with_capacity(request.items.len());
                    let mut result_reservations = Vec::with_capacity(request.items.len());
                    let secrets = prepared.secrets;
                    let selectors = resolved.selectors;
                    let _binding = binding;
                    let _keys = resolved.reservations;
                    let mut env = dispatch::Env {
                        engine: &engine,
                        documents: &mut documents,
                        secrets: &secrets,
                        selectors: &selectors,
                        staging: None,
                        host: &host_policy,
                    };
                    for item in request.items {
                        let (result, reservation, _) =
                            dispatch::run(item.operation, &item.id, &mut env, ctx, None).map_err(
                                |error| match error {
                                    OperationError::Processing(error) => error,
                                    _ => {
                                        ProcessingError::InvalidInput("operation execution failed")
                                    }
                                },
                            )?;
                        result_reservations.push(reservation);
                        results.push(ItemResult {
                            item_id: item.id,
                            applied: dispatch::applied_of(&result),
                            result,
                        });
                    }
                    let reservation = ctx.resources().reserve_metadata(JSON_BYTES)?;
                    let event = ResponseEvent::Final {
                        operation_id: ctx.id().get(),
                        status: FinalStatus::Completed,
                        results,
                        error: None,
                    };
                    let bytes = serde_json::to_vec(&event)
                        .map_err(|_| ProcessingError::InvalidInput("response serialization"))?;
                    if bytes.len() as u64 > JSON_BYTES {
                        return Err(ProcessingError::MetadataLimit);
                    }
                    ctx.resources().account_output(bytes.len() as u64)?;
                    Ok((bytes, reservation))
                })
                .await
                .map_err(|error| processing_error(failure.recover(error)))?;
            let output = await_worker(work, deadline, &failure).await?;
            let ((bytes, reservation), mut ctx) = (output.value, output.context);
            let delivery = ResponseDelivery {
                deadline,
                cancel,
                control: ctx.resources().operation_control(),
                _disconnect: disconnect.clone(),
            };
            delivery.checkpoint().map_err(processing_error)?;
            let owner = ResponseOwner {
                _disconnect: disconnect,
                bytes,
                _context: ctx,
                _reservation: reservation,
            };
            let mut response = Body::new(DeliveryBody {
                data: Some(Bytes::from_owner(owner)),
                delivery: delivery.clone(),
            })
            .into_response();
            response.extensions_mut().insert(delivery);
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            Ok(response)
        })
    }
}
