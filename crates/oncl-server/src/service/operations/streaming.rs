use super::*;
use super::{
    artifact::{ArtifactStore, FinishedArtifact},
    ownership::{ContextGuard, OperationOutput},
    progress::{ProgressHub, Snapshot},
};
use axum::response::Response;
use futures_util::stream;
use std::{collections::VecDeque, future::Future, pin::Pin};
use tokio::sync::{oneshot, watch};

use crate::telemetry::{Applied, ErrorClass, Observer, OperationKind};

pub(super) struct StreamRuntime {
    pub engine: Arc<Engine>,
    pub executor: BoundedExecutor,
    pub source_store: Option<oncl_pki::io::TemporaryStore>,
    pub output_store: Arc<ArtifactStore>,
    pub delivery: ResponseDelivery,
    pub progress: Arc<ProgressHub>,
    pub receiver: watch::Receiver<Snapshot>,
    pub failure: Arc<intake::Failure>,
}
pub(super) type Recheck = Box<dyn Fn(&OperationMetadata) -> Result<(), ApiError> + Send + Sync>;
pub(super) struct PrivateState {
    pub selectors: std::collections::HashMap<String, Vec<oncl_core::keys::KeySelector>>,
    pub reservations: Vec<ResourceReservation>,
    pub binding: Option<crate::audit::AuditBinding>,
    pub host: Arc<super::HostPolicy>,
    pub caller: oncl_core::plugins::CallerContext,
    /// Re-runs principal/generation, per-key and per-(token,plugin,operation)
    /// authorization after the body is fully taken, before any private use.
    pub recheck: Recheck,
}
pub(super) struct StreamFinal {
    pub(super) event: Bytes,
    pub(super) artifacts: Vec<(String, FinishedArtifact)>,
}
/// Minimum spacing of progress frames: latest state, not one frame per native checkpoint.
/// Bound: at most 2 frames/s, i.e. progress output <= 2 * operation deadline (seconds) frames
/// instead of O(native checkpoints); it is not a replacement for the output cap.
const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
type WorkFuture = Pin<Box<dyn Future<Output = Result<StreamFinal, ProcessingError>> + Send>>;

/// Which terminal protocol the native work follows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// `/v1/operations`: sequential items, a failed item withholds every artifact.
    Operations,
    /// `/v1/batch`: SDK closed batch; completed items keep their artifacts.
    Batch,
}
pub(super) async fn response(
    runtime: StreamRuntime,
    mut ctx: OperationContext,
    prepared: intake::Prepared,
    documents: intake::Documents,
    private: PrivateState,
    mode: Mode,
) -> Result<Response, ApiError> {
    // Item IDs for per-item progress parts: bounded by the validated manifest and
    // reserved under the original scope until the response body drops.
    let ids: Option<(Arc<[Box<str>]>, ResourceReservation)> = if mode == Mode::Batch {
        let ids: Arc<[Box<str>]> = prepared
            .metadata
            .items
            .iter()
            .map(|item| item.id.as_str().into())
            .collect();
        let bytes = ids.iter().map(|id| id.len() as u64 + 16).sum::<u64>() + 64;
        let reservation = ctx
            .resources()
            .reserve_metadata(bytes)
            .map_err(processing_error)?;
        Some((ids, reservation))
    } else {
        None
    };
    let started = std::time::Instant::now();
    let observer = Observer::current();
    let deadline = runtime.delivery.deadline;
    let failure = runtime.failure.clone();
    let executor = runtime.executor.clone();
    let body_executor = executor.clone();
    let receiver = runtime.receiver;
    let delivery = runtime.delivery.clone();
    let worker_engine = runtime.engine;
    let worker_failure = failure.clone();
    let (native_ready, ready) = oneshot::channel();
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
            let mut documents = documents;
            if let Err(api) = (private.recheck)(&metadata) {
                let _ = native_ready.send(Err(api));
                return Err(ProcessingError::InvalidInput("authorization changed"));
            }
            if let Err(api) = dispatch::memory_preflight(
                &metadata,
                &mut documents,
                &private.host,
                guard.context().resources(),
            ) {
                let _ = native_ready.send(Err(api));
                return Err(ProcessingError::InvalidInput("memory preflight refused"));
            }
            let secrets = prepared.secrets;
            let PrivateState {
                selectors,
                reservations,
                binding,
                host,
                caller,
                recheck: _,
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
                    subcode: None,
                };
                match mode {
                    Mode::Operations => {
                        let _ = native_ready.send(Ok(root.clone()));
                        execute(&root, &runtime.output_store, &mut guard, metadata, &mut env)
                    }
                    Mode::Batch => {
                        let mut slot = Some(native_ready);
                        super::batch::execute(
                            super::batch::Run {
                                root: &root,
                                store: &runtime.output_store,
                                hub: &runtime.progress,
                                recheck: &*private.recheck,
                            },
                            &mut guard,
                            metadata,
                            &mut env,
                            // Sent exactly once, after host approval of the captured plan and
                            // before the first item: the response status is decided here.
                            &mut |outcome| {
                                if let Some(sender) = slot.take() {
                                    let _ = sender.send(outcome.map(|()| root.clone()));
                                }
                            },
                        )
                    }
                }
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
        next_progress: tokio::time::Instant::now(),
        handed_terminal: false,
        ids,
        route: mode,
        started,
        observer,
        reported: false,
    };
    let body = Body::from_stream(stream::unfold(state, |mut state| async move {
        match state.next().await {
            Ok(Some(bytes)) => Some((Ok::<_, ProcessingError>(bytes), state)),
            Ok(None) => None,
            Err(error) => {
                state.phase = Phase::Done;
                state.report_abort(&error);
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
    for (index, item) in metadata.items.into_iter().enumerate() {
        root.trace()
            .begin_item(index, OperationKind::of(&item.operation));
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
                let failure = match dispatch::classify(error, applied_any, env.subcode.take()) {
                    dispatch::Failure::Abort(error) => return Err(error),
                    dispatch::Failure::Typed(failure) => failure,
                };
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
        root.trace().item_done(item_applied);
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
    Pacing,
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
    receiver: watch::Receiver<Snapshot>,
    work: Option<WorkFuture>,
    boundary: String,
    pending: VecDeque<Bytes>,
    terminal: Option<StreamFinal>,
    artifact: usize,
    offset: u64,
    phase: Phase,
    next_progress: tokio::time::Instant,
    handed_terminal: bool,
    ids: Option<(Arc<[Box<str>]>, ResourceReservation)>,
    route: Mode,
    started: std::time::Instant,
    observer: Observer,
    /// The abort was reported (logged and counted) already: once per stream.
    reported: bool,
}
/// The `ProcessingError` variant of an abort, by name only: the payload of `InvalidInput`
/// and `Io` (developer text, an OS error) never reaches a log.
fn cause_name(error: &ProcessingError) -> &'static str {
    match error {
        ProcessingError::Cancelled => "Cancelled",
        ProcessingError::DeadlineExceeded => "DeadlineExceeded",
        ProcessingError::CapacityExceeded => "CapacityExceeded",
        ProcessingError::InputLimit => "InputLimit",
        ProcessingError::ContainerLimit => "ContainerLimit",
        ProcessingError::FramingLimit => "FramingLimit",
        ProcessingError::OutputLimit => "OutputLimit",
        ProcessingError::MemoryLimit => "MemoryLimit",
        ProcessingError::TempLimit => "TempLimit",
        ProcessingError::MetadataLimit => "MetadataLimit",
        ProcessingError::InvalidLimits => "InvalidLimits",
        ProcessingError::InvalidInput(_) => "InvalidInput",
        ProcessingError::Io(_) => "Io",
    }
}
/// The facts of one aborted stream: numbers and closed names only. Nothing here is built
/// from the text of an error, an item id, a part name, a document, a key, a URL or a path.
struct AbortReport {
    operation: u64,
    route: &'static str,
    item: Option<(u32, &'static str)>,
    class: ErrorClass,
    cause: &'static str,
    applied: oncl_api::error::AppliedState,
    elapsed_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
}
impl AbortReport {
    fn new(
        error: &ProcessingError,
        trace: &ownership::Trace,
        stream: (u64, Mode, std::time::Duration),
        bytes: (u64, u64),
    ) -> Self {
        let (operation, mode, elapsed) = stream;
        Self {
            operation,
            route: match mode {
                Mode::Operations => "operations",
                Mode::Batch => "batch",
            },
            item: trace.current().map(|(index, kind)| (index, kind.as_str())),
            class: ErrorClass::new(processing_code(error)),
            cause: cause_name(intake::first_cause(error)),
            applied: trace.applied(),
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            bytes_in: bytes.0,
            bytes_out: bytes.1,
        }
    }
}
impl std::fmt::Display for AbortReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "oncl-server: stream aborted: operation={} route={} ",
            self.operation, self.route
        )?;
        match self.item {
            Some((index, kind)) => write!(f, "item={index} kind={kind} ")?,
            None => f.write_str("item=none kind=none ")?,
        }
        write!(
            f,
            "code={} cause={} applied={} elapsed_ms={} bytes_in={} bytes_out={}",
            self.class.as_str(),
            self.cause,
            Applied(self.applied).as_str(),
            self.elapsed_ms,
            self.bytes_in,
            self.bytes_out
        )
    }
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
        let snapshot = *self.receiver.borrow_and_update();
        let progress = snapshot.progress;
        let mut value = serde_json::json!({"type":"progress","operation_id":self.root.id().get(),"bytes_in":progress.bytes_in,"bytes_out":progress.bytes_out});
        if let (Some(items), Some((ids, _))) = (snapshot.items, &self.ids) {
            let current = items.current.and_then(|index| {
                ids.get(index as usize)
                    .map(|id| serde_json::json!({"index":index,"item_id":&**id}))
            });
            value["items"] = serde_json::json!({"total":items.total,"finished":items.finished,"current":current});
        }
        let event = self.root.json_event(&value)?;
        self.next_progress = tokio::time::Instant::now() + PROGRESS_INTERVAL;
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
                            if changed.is_ok(){self.phase=Phase::Pacing;}
                            else{self.terminal=Some(self.work.take().expect("native result").await?);self.phase=Phase::ArtifactHeader;}
                        }
                    }
                }
                Phase::Pacing => {
                    // Latest state wins: wait out the rest of the interval (the work result,
                    // and the deadline/cancel checkpoint above, still end the wait), then emit
                    // one frame carrying whatever the producer reached meanwhile.
                    let work = self.work.as_mut().expect("active native result");
                    tokio::select! {
                        result=work=>{self.terminal=Some(result?);self.work=None;self.phase=Phase::ArtifactHeader;},
                        () = tokio::time::sleep_until(self.next_progress) => {
                            self.progress_part()?;
                            self.phase = Phase::Waiting;
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
    /// The server cuts the response short after the 200 head: the client sees only a lost
    /// response, so the typed cause is reported here, on the server, exactly once (a log
    /// line on stderr and a `tracing` event, and the `oncl.stream.aborted` counter). Every
    /// field is a number or a closed name; no document, item id, key, URL or message.
    fn report_abort(&mut self, error: &ProcessingError) {
        use std::io::Write;
        if std::mem::replace(&mut self.reported, true) {
            return;
        }
        let progress = self.receiver.borrow().progress;
        let report = AbortReport::new(
            error,
            self.root.trace(),
            (self.root.id().get(), self.route, self.started.elapsed()),
            (progress.bytes_in, progress.bytes_out),
        );
        // A closed stderr must never panic a response stream: `eprintln!` would.
        let _ = writeln!(std::io::stderr().lock(), "{report}");
        tracing::error!(
            target: "oncl::stream_abort",
            operation = report.operation,
            route = report.route,
            item = report.item.map_or(-1, |(index, _)| i64::from(index)),
            kind = report.item.map_or("none", |(_, kind)| kind),
            code = report.class.as_str(),
            cause = report.cause,
            applied = Applied(report.applied).as_str(),
            elapsed_ms = report.elapsed_ms,
            bytes_in = report.bytes_in,
            bytes_out = report.bytes_out,
            "response stream aborted after the head"
        );
        self.observer.stream_aborted(report.class, report.applied);
    }
}
impl Drop for StreamState {
    fn drop(&mut self) {
        if !self.handed_terminal {
            self.root.delivery().cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_api::error::AppliedState;
    use std::time::Duration;

    fn line(error: &ProcessingError, trace: &ownership::Trace) -> String {
        AbortReport::new(
            error,
            trace,
            (7, Mode::Operations, Duration::from_millis(42)),
            (3, 218),
        )
        .to_string()
    }

    /// The line is the contract operators grep: exact shape, closed names, numbers.
    #[test]
    fn the_line_names_the_typed_cause_and_where_the_operation_stood() {
        let trace = ownership::Trace::default();
        trace.begin_item(0, OperationKind::Hash);
        trace.item_done(AppliedState::NotApplied);
        trace.begin_item(2, OperationKind::Verify);
        assert_eq!(
            line(&ProcessingError::MetadataLimit, &trace),
            "oncl-server: stream aborted: operation=7 route=operations item=2 kind=verify \
             code=metadata_limit cause=MetadataLimit applied=not_applied elapsed_ms=42 \
             bytes_in=3 bytes_out=218"
        );
        trace.item_done(AppliedState::Applied);
        assert!(line(&ProcessingError::OutputLimit, &trace).contains("applied=applied "));
        trace.item_done(AppliedState::Unknown);
        trace.item_done(AppliedState::NotApplied);
        assert!(
            line(&ProcessingError::DeadlineExceeded, &trace).contains("applied=unknown "),
            "a later keyless item never lowers an earlier state"
        );
        assert!(
            line(&ProcessingError::Cancelled, &ownership::Trace::default()).contains(
                "item=none kind=none code=cancelled cause=Cancelled applied=not_applied "
            )
        );
    }

    /// An error's own text can carry a path, an OS message or a developer string: only its
    /// variant name and closed code are ever written.
    #[test]
    fn the_line_never_carries_the_text_of_an_error() {
        let trace = ownership::Trace::default();
        let io = ProcessingError::Io(std::io::Error::other(
            "CANARY os message about secret-contract.pdf",
        ));
        let text = line(&io, &trace);
        assert!(text.contains("code=invalid_request cause=Io "), "{text}");
        assert!(
            !text.contains("CANARY") && !text.contains("secret"),
            "{text}"
        );
        let invalid = ProcessingError::InvalidInput("CANARY-developer-string");
        let text = line(&invalid, &trace);
        assert!(
            text.contains("code=invalid_request cause=InvalidInput "),
            "{text}"
        );
        assert!(!text.contains("CANARY"), "{text}");
    }

    /// The first cause behind the shared-failure carrier is what is reported, not the
    /// carrier's own generic I/O shape.
    #[test]
    fn the_first_cause_behind_a_shared_failure_is_reported() {
        let failure = intake::Failure::default();
        failure.record(ProcessingError::MetadataLimit);
        let carried = failure.recover(ProcessingError::InvalidInput("fallback"));
        let text = line(&carried, &ownership::Trace::default());
        assert!(
            text.contains("code=metadata_limit cause=MetadataLimit "),
            "{text}"
        );
    }
}
