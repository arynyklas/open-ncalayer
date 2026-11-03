mod intake;

use super::*;
use oncl_api::dto::{
    FinalStatus, HashAlgorithm, ItemResult, Operation, OperationMetadata, OperationResult,
    PartRole, ResponseEvent,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const JSON_BYTES: u64 = 65_536;
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
    for item in &metadata.items {
        if !identifier(&item.id) || !ids.insert(item.id.as_str()) {
            return Err(invalid_request());
        }
        let Operation::Hash { input, .. } = &item.operation;
        let part = metadata
            .parts
            .iter()
            .find(|p| p.name == *input)
            .ok_or_else(invalid_request)?;
        if part.item_id != item.id || part.role != PartRole::Document {
            return Err(invalid_request());
        }
    }
    for part in &metadata.parts {
        if !identifier(&part.name)
            || !names.insert(part.name.as_str())
            || part.role != PartRole::Document
        {
            return Err(invalid_request());
        }
        if !metadata.items.iter().any(|i|matches!(&i.operation,Operation::Hash{input,..} if *input==part.name && i.id==part.item_id)) {return Err(invalid_request());}
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
        Box::pin(async move {
            let deadline = deadline?;
            let principal = principal?;
            let disconnect = Arc::new(CancelOnDrop(cancel.clone()));
            let mut admission = engine
                .admit(Arc::new(InvocationControl {
                    cancel: cancel.clone(),
                    deadline,
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
            let prepared =
                intake::prepare(&metadata, body, &mut admission, deadline, cancel.clone()).await?;
            // Recheck the actual Principal generation and each resolved operation
            // after bounded metadata intake, before the first SDK dispatch.
            let grant = policy
                .authorize(&principal, Action::Hash, None, None)
                .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?;
            let ctx = engine
                .begin_admitted(admission, grant, OperationPolicy::strict_online())
                .map_err(core_error)?;
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
                    for item in request.items {
                        let Operation::Hash {
                            algorithm: hash,
                            input,
                        } = item.operation;
                        let (report, bytes_in) = match &mut documents {
                            intake::Documents::Text(documents) => {
                                let document = documents
                                    .get(&input)
                                    .ok_or(ProcessingError::InvalidInput("missing document"))?;
                                engine
                                    .hash(
                                        algorithm(hash),
                                        Source::sequential(
                                            &mut document.as_bytes(),
                                            Some(document.len() as u64),
                                        ),
                                        ctx,
                                    )
                                    .map(|r| (r, document.len() as u64))
                            }
                            intake::Documents::Frozen(documents) => {
                                let document = documents
                                    .get_mut(&input)
                                    .ok_or(ProcessingError::InvalidInput("missing document"))?;
                                let length = document.len();
                                let mut reader = document.reader(
                                    &[oncl_pki::io::Region {
                                        offset: 0,
                                        len: length,
                                    }],
                                    ctx.resources(),
                                )?;
                                let result = engine.hash(algorithm(hash), reader.source(), ctx);
                                reader.finish()?;
                                result.map(|r| (r, length))
                            }
                        }
                        .map_err(|e| match e {
                            OperationError::Processing(e) => e,
                            _ => ProcessingError::InvalidInput("operation failed"),
                        })?;
                        results.push(ItemResult {
                            item_id: item.id,
                            applied: oncl_api::error::AppliedState::NotApplied,
                            result: OperationResult::Hash {
                                algorithm: hash,
                                digest: crate::auth::encode(report.digest.as_bytes()),
                                bytes_in,
                            },
                        });
                    }
                    let reservation = ctx.resources().reserve_metadata(JSON_BYTES)?;
                    let event = ResponseEvent::Final {
                        operation_id: ctx.id().get(),
                        status: FinalStatus::Completed,
                        results,
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
                .map_err(processing_error)?;
            let output = tokio::time::timeout(deadline.remaining(), work.wait())
                .await
                .map_err(|_| ApiError::not_applied(ErrorCode::DeadlineExceeded))?
                .map_err(processing_error)?;
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
