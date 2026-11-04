use super::*;
use super::{
    artifact::{ArtifactStore, FinishedArtifact},
    ownership::{ContextGuard, OperationOutput},
    progress::ProgressHub,
};
use axum::response::Response;
use futures_util::stream;
use std::{collections::VecDeque, future::Future, pin::Pin};
use tokio::sync::{oneshot, watch};

pub(super) struct StreamRuntime {
    pub engine: Arc<Engine>,
    pub executor: BoundedExecutor,
    pub source_store: Option<oncl_pki::io::TemporaryStore>,
    pub output_store: Arc<ArtifactStore>,
    pub delivery: ResponseDelivery,
    pub progress: Arc<ProgressHub>,
    pub receiver: watch::Receiver<Progress>,
    pub failure: Arc<intake::Failure>,
}
pub(super) struct PrivateState {
    pub selectors: std::collections::HashMap<String, Vec<oncl_core::keys::KeySelector>>,
    pub reservations: Vec<ResourceReservation>,
    pub binding: Option<crate::audit::AuditBinding>,
    pub host: Arc<super::HostPolicy>,
    pub caller: oncl_core::plugins::CallerContext,
}
struct StreamFinal {
    event: Bytes,
    artifacts: Vec<(String, FinishedArtifact)>,
}
type WorkFuture = Pin<Box<dyn Future<Output = Result<StreamFinal, ProcessingError>> + Send>>;

pub(super) async fn response(
    runtime: StreamRuntime,
    ctx: OperationContext,
    prepared: intake::Prepared,
    private: PrivateState,
) -> Result<Response, ApiError> {
    let deadline = runtime.delivery.deadline;
    let failure = runtime.failure.clone();
    let executor = runtime.executor.clone();
    let body_executor = executor.clone();
    let receiver = runtime.receiver;
    let delivery = runtime.delivery.clone();
    let worker_engine = runtime.engine;
    let worker_failure = failure.clone();
    let (native_ready, ready) = oneshot::channel();
    let handle = tokio::runtime::Handle::current();
    let work = executor
        .submit_owned(ctx, move |ctx| {
            let native = runtime.progress.native()?;
            let output_count = prepared
                .metadata
                .items
                .iter()
                .filter(|item| dispatch::has_output(&item.operation))
                .count();
            let (root, mut guard) = match OperationOutput::new(
                worker_engine.clone(),
                ctx,
                runtime.delivery,
                worker_failure.clone(),
                output_count,
            ) {
                Ok(output) => output,
                Err(error) => {
                    worker_failure.record(error);
                    let _ = native_ready
                        .send(Err(processing_error(worker_failure.recover(
                            ProcessingError::InvalidInput("output admission failed"),
                        ))));
                    return Err(worker_failure
                        .recover(ProcessingError::InvalidInput("output admission failed")));
                }
            };
            let _reservations = prepared.reservations;
            let metadata = prepared.metadata;
            let mut documents = match prepared.payload.capture(
                &metadata,
                runtime.source_store.as_ref(),
                guard.context(),
                handle,
            ) {
                Ok(documents) => documents,
                Err(error) => {
                    let _ = native_ready.send(Err(processing_error(worker_failure.recover(error))));
                    return Err(
                        worker_failure.recover(ProcessingError::InvalidInput("intake failed"))
                    );
                }
            };
            let _ = native_ready.send(Ok(root.clone()));
            let secrets = prepared.secrets;
            let PrivateState {
                selectors,
                reservations,
                binding,
                host,
                caller,
            } = private;
            let result = {
                let mut env = dispatch::Env {
                    engine: &worker_engine,
                    documents: &mut documents,
                    secrets: &secrets,
                    selectors: &selectors,
                    staging: runtime.source_store.as_ref(),
                    host: &host,
                    caller: &caller,
                };
                execute(&root, &runtime.output_store, &mut guard, metadata, &mut env)
            };
            // Secrets, selector copies and the audit binding end with native work.
            drop(secrets);
            drop(selectors);
            drop(reservations);
            drop(binding);
            drop(native);
            guard.complete()?;
            result
        })
        .await
        .map_err(|error| processing_error(failure.recover(error)))?;
    let root = match tokio::time::timeout(deadline.remaining(), ready).await {
        Ok(Ok(result)) => result?,
        Ok(Err(_)) => {
            let result = super::await_worker(work, deadline, &failure).await;
            return match result {
                Err(error) => Err(error),
                Ok(_) => Err(ApiError::not_applied(ErrorCode::Internal)),
            };
        }
        Err(_) => {
            return Err(processing_error(
                failure.recover(ProcessingError::DeadlineExceeded),
            ));
        }
    };
    let (mut boundary, _) =
        super::artifact::random_component("oncl-response-").map_err(processing_error)?;
    if boundary.len() > 70 {
        return Err(ApiError::not_applied(ErrorCode::Internal));
    }
    let content_type = HeaderValue::from_str(&format!("multipart/mixed; boundary={boundary}"))
        .map_err(|_| ApiError::not_applied(ErrorCode::Internal))?;
    let state = StreamState {
        root,
        executor: body_executor,
        receiver,
        work: Some(Box::pin(work.wait())),
        boundary: std::mem::take(&mut boundary),
        pending: VecDeque::with_capacity(3),
        terminal: None,
        artifact: 0,
        offset: 0,
        phase: Phase::Initial,
        handed_terminal: false,
    };
    let body = Body::from_stream(stream::unfold(state, |mut state| async move {
        match state.next().await {
            Ok(Some(bytes)) => Some((Ok::<_, ProcessingError>(bytes), state)),
            Ok(None) => None,
            Err(error) => {
                state.phase = Phase::Done;
                Some((Err(error), state))
            }
        }
    }));
    let mut response = body.into_response();
    response.extensions_mut().insert(delivery);
    response.headers_mut().insert("content-type", content_type);
    Ok(response)
}
fn execute(
    root: &Arc<OperationOutput>,
    store: &Arc<ArtifactStore>,
    guard: &mut ContextGuard,
    metadata: OperationMetadata,
    env: &mut dispatch::Env<'_>,
) -> Result<StreamFinal, ProcessingError> {
    let mut results: Vec<ItemResult> = Vec::with_capacity(metadata.items.len());
    let mut reservations = Vec::with_capacity(metadata.items.len());
    let mut artifacts = Vec::new();
    let mut applied_any = false;
    for item in metadata.items {
        let id = format!("artifact-{}", artifacts.len());
        let outcome = dispatch::run(
            item.operation,
            &item.id,
            env,
            guard.context(),
            Some(dispatch::ArtifactSink {
                store,
                owner: root,
                id: id.clone(),
            }),
        );
        let (result, reservation, artifact) = match outcome {
            Ok(done) => done,
            Err(error) => {
                let failure = operation_failure(&error);
                let applied = failure.applied != oncl_api::error::AppliedState::NotApplied;
                // Resource/deadline/cancel failures that never applied a key stay a
                // transport abort (the original first-fatal cause); anything that
                // may have used a private key, and every typed SDK refusal, gets a
                // terminal failed record carrying the honest Applied state.
                let abort = matches!(
                    &error,
                    OperationError::Processing(e)
                        if !matches!(intake::first_cause(e), ProcessingError::InvalidInput(_))
                );
                if abort && !applied && !applied_any {
                    return Err(match error {
                        OperationError::Processing(error) => error,
                        _ => unreachable!("matched processing"),
                    });
                }
                // Artifacts of this request are withheld: no partial success, and
                // no Content-ID of undelivered output remains in the results.
                drop(artifacts);
                drop(reservations);
                for item in &mut results {
                    item.result.withhold_artifact();
                }
                let event = root.json_event(&ResponseEvent::Final {
                    operation_id: root.id().get(),
                    status: FinalStatus::Failed,
                    results,
                    error: Some(failure),
                })?;
                return Ok(StreamFinal {
                    event,
                    artifacts: Vec::new(),
                });
            }
        };
        reservations.push(reservation);
        let item_applied = dispatch::applied_of(&result);
        applied_any |= item_applied != oncl_api::error::AppliedState::NotApplied;
        if let Some(artifact) = artifact {
            artifacts.push((id, artifact));
        }
        results.push(ItemResult {
            item_id: item.id,
            applied: item_applied,
            result,
        });
    }
    let event = root.json_event(&ResponseEvent::Final {
        operation_id: root.id().get(),
        status: FinalStatus::Completed,
        results,
        error: None,
    })?;
    Ok(StreamFinal { event, artifacts })
}
#[derive(Clone, Copy)]
enum Phase {
    Initial,
    Waiting,
    ArtifactHeader,
    ArtifactData,
    ArtifactEnd,
    Final,
    Closing,
    Done,
}
struct StreamState {
    root: Arc<OperationOutput>,
    executor: BoundedExecutor,
    receiver: watch::Receiver<Progress>,
    work: Option<WorkFuture>,
    boundary: String,
    pending: VecDeque<Bytes>,
    terminal: Option<StreamFinal>,
    artifact: usize,
    offset: u64,
    phase: Phase,
    handed_terminal: bool,
}
impl StreamState {
    fn json_part(&mut self, name: &str, event: Bytes) -> Result<(), ProcessingError> {
        let header = format!(
            "--{}\r\nContent-Type: application/json\r\nContent-Disposition: form-data; name=\"{}\"\r\nContent-Length: {}\r\n\r\n",
            self.boundary,
            name,
            event.len()
        );
        self.pending
            .push_back(self.root.protocol_frame(header.as_bytes())?);
        self.pending.push_back(event);
        self.pending.push_back(self.root.protocol_frame(b"\r\n")?);
        Ok(())
    }
    fn progress_part(&mut self) -> Result<(), ProcessingError> {
        let progress = *self.receiver.borrow_and_update();
        let event=self.root.json_event(&serde_json::json!({"type":"progress","operation_id":self.root.id().get(),"bytes_in":progress.bytes_in,"bytes_out":progress.bytes_out}))?;
        self.json_part("progress", event)
    }
    async fn next(&mut self) -> Result<Option<Bytes>, ProcessingError> {
        loop {
            self.root.delivery().checkpoint()?;
            if let Some(bytes) = self.pending.pop_front() {
                return Ok(Some(bytes));
            }
            match self.phase {
                Phase::Initial => {
                    self.progress_part()?;
                    self.phase = Phase::Waiting;
                }
                Phase::Waiting => {
                    let work = self.work.as_mut().expect("active native result");
                    tokio::select! {
                        result=work=>{self.terminal=Some(result?);self.work=None;self.phase=Phase::ArtifactHeader;},
                        changed=self.receiver.changed()=>{
                            if changed.is_ok(){self.progress_part()?;}
                            else{self.terminal=Some(self.work.take().expect("native result").await?);self.phase=Phase::ArtifactHeader;}
                        }
                    }
                }
                Phase::ArtifactHeader => {
                    let terminal = self.terminal.as_ref().expect("terminal result");
                    if self.artifact >= terminal.artifacts.len() {
                        self.phase = Phase::Final;
                        continue;
                    }
                    let (id, artifact) = &terminal.artifacts[self.artifact];
                    let header = format!(
                        "--{}\r\nContent-Type: application/octet-stream\r\nContent-Disposition: form-data; name=\"artifact\"\r\nContent-ID: {}\r\nContent-Length: {}\r\n\r\n",
                        self.boundary,
                        id,
                        artifact.len()
                    );
                    self.phase = Phase::ArtifactData;
                    return Ok(Some(self.root.protocol_frame(header.as_bytes())?));
                }
                Phase::ArtifactData => {
                    let artifact = &self.terminal.as_ref().expect("terminal result").artifacts
                        [self.artifact]
                        .1;
                    if self.offset == artifact.len() {
                        self.phase = Phase::ArtifactEnd;
                        continue;
                    }
                    let task = artifact.read_task(self.root.clone(), self.offset)?;
                    let result = self.executor.read_output(task).await?.wait().await?;
                    self.offset = result.next;
                    return Ok(Some(result.bytes));
                }
                Phase::ArtifactEnd => {
                    self.artifact += 1;
                    self.offset = 0;
                    self.phase = Phase::ArtifactHeader;
                    return Ok(Some(self.root.protocol_frame(b"\r\n")?));
                }
                Phase::Final => {
                    let event = self.terminal.take().expect("terminal result").event;
                    self.json_part("final", event)?;
                    self.phase = Phase::Closing;
                }
                Phase::Closing => {
                    self.phase = Phase::Done;
                    self.handed_terminal = true;
                    return Ok(Some(self.root.protocol_frame(
                        format!("--{}--\r\n", self.boundary).as_bytes(),
                    )?));
                }
                Phase::Done => return Ok(None),
            }
        }
    }
}
impl Drop for StreamState {
    fn drop(&mut self) {
        if !self.handed_terminal {
            self.root.delivery().cancel.cancel();
        }
    }
}
