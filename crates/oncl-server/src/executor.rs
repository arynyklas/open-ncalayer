//! Admission is finite BEFORE spawn_blocking. Cancellation drops the receiver,
//! not a running native closure or its worker/resource permits.
use crate::telemetry::{Observer, Stage};
use oncl_core::{OperationAdmission, OperationContext};
use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceScope};
use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::{Notify, Semaphore, oneshot};

#[derive(Clone, Copy, Debug)]
pub struct ExecutorConfig {
    pub blocking_workers: usize,
    pub queue_capacity: usize,
    pub admission_wait: Duration,
}
impl ExecutorConfig {
    pub fn validate(&self) -> Result<(), ProcessingError> {
        if self.blocking_workers == 0
            || self.blocking_workers > 64
            || self.queue_capacity > 256
            || self.admission_wait.is_zero()
            || std::time::Instant::now()
                .checked_add(self.admission_wait)
                .is_none()
        {
            return Err(ProcessingError::InvalidLimits);
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct Cancellation {
    cancelled: AtomicBool,
    changed: Notify,
}
impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub async fn cancelled(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}
impl OperationControl for Cancellation {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
pub struct CancelOnDrop(pub Arc<Cancellation>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct Shared {
    config: ExecutorConfig,
    workers: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    waiting: AtomicUsize,
    running: AtomicUsize,
    idle: Notify,
}
#[derive(Clone)]
pub struct BoundedExecutor {
    shared: Arc<Shared>,
}
pub struct WorkOutput<T> {
    pub value: T,
    pub context: OperationContext,
}
pub struct WorkHandle<T> {
    receiver: oneshot::Receiver<Result<T, ProcessingError>>,
    abandoned: Arc<Cancellation>,
    deadline: oncl_pki::resource::Deadline,
}
impl<T> WorkHandle<T> {
    pub async fn wait(mut self) -> Result<T, ProcessingError> {
        match tokio::time::timeout(self.deadline.remaining(), &mut self.receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ProcessingError::Cancelled),
            Err(_) => Err(ProcessingError::DeadlineExceeded),
        }
    }
}
impl<T> Drop for WorkHandle<T> {
    fn drop(&mut self) {
        self.abandoned.cancel();
    }
}
struct Active {
    shared: Arc<Shared>,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for Active {
    fn drop(&mut self) {
        drop(self.slot.take());
        self.shared.idle.notify_waiters();
    }
}
struct Running(Arc<Shared>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Waiting(Arc<Shared>);
impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Non-owning load view: never keeps the executor (or its permits) alive.
#[derive(Clone)]
pub(crate) struct LoadProbe(Weak<Shared>);
impl LoadProbe {
    /// `(running, queued)` while the executor exists.
    pub(crate) fn load(&self) -> Option<(usize, usize)> {
        let shared = self.0.upgrade()?;
        Some((
            shared.running.load(Ordering::Acquire),
            shared.waiting.load(Ordering::Acquire),
        ))
    }
}
impl BoundedExecutor {
    /// Weak view of the executor load for the optional busy/queued gauges.
    pub(crate) fn load_probe(&self) -> LoadProbe {
        LoadProbe(Arc::downgrade(&self.shared))
    }
    pub fn new(config: ExecutorConfig) -> Result<Self, ProcessingError> {
        config.validate()?;
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                workers: Arc::new(Semaphore::new(config.blocking_workers)),
                slots: Arc::new(Semaphore::new(
                    config.blocking_workers + config.queue_capacity,
                )),
                waiting: AtomicUsize::new(0),
                running: AtomicUsize::new(0),
                idle: Notify::new(),
            }),
        })
    }
    pub fn running(&self) -> usize {
        self.shared.running.load(Ordering::Acquire)
    }
    pub fn queued(&self) -> usize {
        self.shared.waiting.load(Ordering::Acquire)
    }
    pub async fn idle(&self) {
        loop {
            let changed = self.shared.idle.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.shared.slots.available_permits()
                == self.shared.config.blocking_workers + self.shared.config.queue_capacity
            {
                return;
            }
            changed.await;
        }
    }
    pub async fn submit<T, F>(
        &self,
        mut ctx: OperationContext,
        work: F,
    ) -> Result<WorkHandle<WorkOutput<T>>, ProcessingError>
    where
        T: Send + 'static,
        F: FnOnce(&mut OperationContext) -> Result<T, ProcessingError> + Send + 'static,
    {
        let scope = ctx.resources().shared_view();
        self.launch(scope, move || {
            work(&mut ctx).map(|value| WorkOutput {
                value,
                context: ctx,
            })
        })
        .await
    }
    /// Consume an original grantless intake admission in the same bounded native
    /// worker pool. Only the host can turn it into an authorized SDK context.
    pub async fn submit_admitted<T, F>(
        &self,
        mut admission: OperationAdmission,
        work: F,
    ) -> Result<WorkHandle<T>, ProcessingError>
    where
        T: Send + 'static,
        F: FnOnce(OperationAdmission) -> Result<T, ProcessingError> + Send + 'static,
    {
        let scope = admission.resources().shared_view();
        self.launch(scope, move || work(admission)).await
    }
    /// Transfer the actual context to a native owner without cloning authority.
    /// Result/output ownership is independent from the native worker permit.
    pub async fn submit_owned<T, F>(
        &self,
        mut ctx: OperationContext,
        work: F,
    ) -> Result<WorkHandle<T>, ProcessingError>
    where
        T: Send + 'static,
        F: FnOnce(OperationContext) -> Result<T, ProcessingError> + Send + 'static,
    {
        let scope = ctx.resources().shared_view();
        self.launch(scope, move || work(ctx)).await
    }
    /// Only the server's sealed finished-artifact task can submit delivery I/O.
    /// A read holds the same native permit until return, never while the socket
    /// waits for its consumer. This does not expose arbitrary scope submission.
    pub(crate) async fn read_output(
        &self,
        task: crate::service::operations::artifact::OutputReadTask,
    ) -> Result<WorkHandle<crate::service::operations::artifact::OutputReadResult>, ProcessingError>
    {
        let scope = task.scope();
        self.launch(scope, move || task.execute()).await
    }
    async fn launch<T, F>(
        &self,
        scope: ResourceScope,
        work: F,
    ) -> Result<WorkHandle<T>, ProcessingError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, ProcessingError> + Send + 'static,
    {
        // Admission of this request ends here: the first hand-off to the executor.
        let observer = Observer::current();
        observer.mark_admitted();
        scope.checkpoint()?;
        let slot = self.shared.slots.clone().try_acquire_owned().map_err(|_| {
            observer.executor_rejected();
            ProcessingError::CapacityExceeded
        })?;
        let active = Active {
            shared: self.shared.clone(),
            slot: Some(slot),
        };
        let immediate = self.shared.workers.clone().try_acquire_owned().ok();
        let waiting = if immediate.is_none() {
            let previous = self.shared.waiting.fetch_add(1, Ordering::AcqRel);
            if previous >= self.shared.config.queue_capacity {
                self.shared.waiting.fetch_sub(1, Ordering::AcqRel);
                observer.executor_rejected();
                return Err(ProcessingError::CapacityExceeded);
            }
            Some(Waiting(self.shared.clone()))
        } else {
            None
        };
        let (sender, receiver) = oneshot::channel();
        let abandoned = Arc::new(Cancellation::new());
        let stop = abandoned.clone();
        let deadline = scope.deadline();
        let shared = self.shared.clone();
        let (queued, queued_time) = (Instant::now(), SystemTime::now());
        tokio::spawn(async move {
            let worker = match immediate {
                Some(permit) => permit,
                None => {
                    let wait = shared.config.admission_wait.min(deadline.remaining());
                    let result = tokio::select! {
                        _ = stop.cancelled() => Err(ProcessingError::Cancelled),
                        result = tokio::time::timeout(wait, shared.workers.clone().acquire_owned()) => match result {
                            Ok(Ok(permit)) => Ok(permit),
                            Ok(Err(_)) => Err(ProcessingError::CapacityExceeded),
                            Err(_) if deadline.is_expired() => Err(ProcessingError::DeadlineExceeded),
                            Err(_) => Err(ProcessingError::CapacityExceeded),
                        }
                    };
                    match result {
                        Ok(permit) => permit,
                        Err(error) => {
                            if matches!(error, ProcessingError::CapacityExceeded) {
                                observer.executor_rejected();
                            }
                            drop(waiting);
                            drop(work);
                            drop(scope);
                            drop(observer);
                            drop(active);
                            let _ = sender.send(Err(error));
                            return;
                        }
                    }
                }
            };
            drop(waiting);
            observer.executor_stage(Stage::Wait, queued, queued_time, None);
            if let Err(error) = scope
                .checkpoint()
                .and_then(|_| stop.checkpoint(Progress::default()))
            {
                drop(work);
                drop(scope);
                drop(worker);
                drop(observer);
                drop(active);
                let _ = sender.send(Err(error));
                return;
            }
            shared.running.fetch_add(1, Ordering::AcqRel);
            let running = Running(shared);
            // Worker permit, admission slot, context and reservations are INSIDE
            // the real closure, never merely inside a cancellable async waiter.
            tokio::task::spawn_blocking(move || {
                let scope = scope;
                let active = active;
                let worker = worker;
                let running = running;
                let observer = observer;
                let entered = observer.enter_worker();
                let (run, run_time) = (Instant::now(), SystemTime::now());
                let result = work();
                observer.executor_stage(
                    Stage::Run,
                    run,
                    run_time,
                    result.as_ref().err().map(crate::service::processing_code),
                );
                // The end, in the order its parts need. The native call is over, so its worker
                // count and permit go before the result is delivered: `send` wakes the
                // receiver, which runs at once on another thread, and whoever sees the result
                // (the response frame of a staged artifact, say) must not see a native worker
                // still running for it. Releasing after `send` is a race the receiver can win.
                drop(running);
                drop(worker);
                // The executor's own share of the operation (a view of its resource scope, which
                // keeps the operation's `max_in_flight` slot taken until its last owner lets go)
                // ends with the native call as well. It must go before `active`: a caller that
                // waits for `idle()` and admits again at once finds the slot free only if no
                // share of the operation outlives the slot of this request. A local that is
                // dropped at the closure's end would be released after `active`, a race.
                drop(scope);
                let _ = sender.send(result);
                // This thread's share of the request goes before the slot. The executor is
                // idle (and a shutdown may flush telemetry) only when `active` is gone, and a
                // request whose last owner is this thread ends its span and metrics when it
                // lets go: the other order exports a service's last request too late. A
                // closure's own capture would be dropped after every local, so the request
                // would end after the executor was seen idle.
                drop(entered);
                drop(observer);
                drop(active);
            });
        });
        Ok(WorkHandle {
            receiver,
            abandoned,
            deadline,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{Route, Telemetry, TelemetryConfig};
    use oncl_pki::resource::{ResourceLimits, SharedBudget};

    fn scope() -> ResourceScope {
        let limits = ResourceLimits::default();
        Arc::new(SharedBudget::new(limits.clone()).unwrap())
            .begin_unslotted(limits, Arc::new(Cancellation::new()))
            .unwrap()
    }

    /// A request ends (its span and metrics are made) when its last owner lets go, and a
    /// shutdown flushes once the executor is idle: so the worker must let go of the request
    /// before it frees the permit that makes the executor idle, or the last request of a
    /// service that is stopped right after its answer is missing from the exported telemetry.
    /// The worker's release is a few instructions behind the permit, so a round is a race and
    /// the rounds are many, with the permit watched by a spin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_executor_is_idle_only_after_its_worker_let_go_of_the_request() {
        let telemetry = Telemetry::start(&TelemetryConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:9".into(),
            shutdown_timeout_ms: 100,
            ..TelemetryConfig::default()
        })
        .unwrap();
        let executor = BoundedExecutor::new(ExecutorConfig {
            blocking_workers: 2,
            queue_capacity: 2,
            admission_wait: Duration::from_secs(1),
        })
        .unwrap();
        let mut late = 0;
        for _ in 0..10_000 {
            let served = executor.clone();
            let response = telemetry
                .begin(Route::Hash)
                .observe(Box::pin(async move {
                    served
                        .launch(scope(), || Ok(()))
                        .await
                        .unwrap()
                        .wait()
                        .await
                        .unwrap();
                    Ok(axum::response::Response::new(axum::body::Body::empty()))
                }))
                .await
                .unwrap();
            // What the client has read: the response is gone, only a worker may still hold on.
            drop(response);
            // The executor's own test of idleness, watched without a wake-up in between: the
            // moment the permit is free is the moment a shutdown may go on to flush.
            let full =
                executor.shared.config.blocking_workers + executor.shared.config.queue_capacity;
            let began = Instant::now();
            while executor.shared.slots.available_permits() != full {
                assert!(began.elapsed() < Duration::from_secs(5), "the worker ends");
                std::hint::spin_loop();
            }
            if telemetry.requests_in_flight() != 0 {
                late += 1;
            }
            // Whatever the race did, the next round starts from nothing in flight.
            while telemetry.requests_in_flight() != 0 {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(late, 0, "rounds whose request outlived the idle executor");
    }

    /// The load of the executor at the moment a result becomes observable. The receiver's
    /// wake-up runs inside `send` (the channel calls the waker after the value is stored, and
    /// before `send` returns), so that moment is a point of the worker's own thread.
    struct LoadAtDelivery {
        executor: BoundedExecutor,
        seen: std::sync::Mutex<Option<(usize, usize)>>,
    }
    impl std::task::Wake for LoadAtDelivery {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            *self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
                self.executor.running(),
                self.executor.shared.workers.available_permits(),
            ));
        }
    }

    /// `running()` and the worker permit account for the native call, which is over when its
    /// result exists: both are released before the result is delivered, so whoever sees the
    /// result (the response frame of a staged artifact, say) never sees a native worker still
    /// running for it. Not a race to be sampled: the result's receiver is woken inside `send`,
    /// on the worker's thread, and records the load there, so a worker that delivers first and
    /// releases after is seen on every run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_native_worker_is_released_before_its_result_is_delivered() {
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Poll, Waker},
        };
        let executor = BoundedExecutor::new(ExecutorConfig {
            blocking_workers: 1,
            queue_capacity: 1,
            admission_wait: Duration::from_secs(1),
        })
        .unwrap();
        let (open, held) = std::sync::mpsc::channel::<()>();
        let mut handle = executor
            .launch(scope(), move || {
                held.recv().expect("the test opens the gate");
                Ok(7u8)
            })
            .await
            .unwrap();
        let load = Arc::new(LoadAtDelivery {
            executor: executor.clone(),
            seen: std::sync::Mutex::new(None),
        });
        let waker = Waker::from(load.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(
            Pin::new(&mut handle.receiver).poll(&mut cx).is_pending(),
            "the worker is held at the gate"
        );
        let began = Instant::now();
        while executor.running() != 1 {
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "the worker starts"
            );
            tokio::task::yield_now().await;
        }
        open.send(()).unwrap();
        let seen = loop {
            if let Some(seen) = *load
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                break seen;
            }
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "the result is delivered"
            );
            tokio::task::yield_now().await;
        };
        assert_eq!(
            seen,
            (0, 1),
            "(running, free native workers) when the result became observable"
        );
        assert!(matches!(
            Pin::new(&mut handle.receiver).poll(&mut cx),
            Poll::Ready(Ok(Ok(7)))
        ));
        executor.idle().await;
    }

    /// The executor's free request slots at the moment the last owner of an operation let go
    /// of it: the guard of the operation's lease is dropped then, and not earlier.
    struct FreeSlotsAtRelease {
        executor: BoundedExecutor,
        seen: Arc<std::sync::Mutex<Option<usize>>>,
    }
    impl Drop for FreeSlotsAtRelease {
        fn drop(&mut self) {
            *self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(self.executor.shared.slots.available_permits());
        }
    }

    /// `idle()` means that nothing of a request is left in the executor, so whoever waits for
    /// it and admits again at once (an engine that runs one operation at a time) finds the
    /// operation's `max_in_flight` slot free. That slot is freed when the last owner of the
    /// operation lets go, and the executor's share of it (a view of the resource scope) is
    /// one of the owners: it must be gone before the executor's own request slot is. Not a
    /// race to be sampled: the lease's guard records the free request slots at the moment the
    /// last owner lets go, on the worker's thread, so a share that is released after the slot
    /// is seen on every run, whether the result is awaited or its receiver is gone already.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_executor_lets_go_of_the_operation_before_it_frees_its_own_slot() {
        for abandoned in [false, true] {
            let executor = BoundedExecutor::new(ExecutorConfig {
                blocking_workers: 1,
                queue_capacity: 1,
                admission_wait: Duration::from_secs(1),
            })
            .unwrap();
            let full =
                executor.shared.config.blocking_workers + executor.shared.config.queue_capacity;
            let seen = Arc::new(std::sync::Mutex::new(None));
            let scope = scope();
            assert!(scope.lease().attach_guard(Box::new(FreeSlotsAtRelease {
                executor: executor.clone(),
                seen: seen.clone(),
            })));
            let (open, held) = std::sync::mpsc::channel::<()>();
            let (entered, started) = oneshot::channel::<()>();
            let handle = executor
                .launch(scope, move || {
                    entered.send(()).expect("the test waits for the start");
                    held.recv().expect("the test opens the gate");
                    Ok(())
                })
                .await
                .unwrap();
            started.await.expect("the native call starts");
            if abandoned {
                // Nobody is left to take the result: the native call runs on, unseen.
                drop(handle);
                open.send(()).unwrap();
            } else {
                open.send(()).unwrap();
                handle.wait().await.unwrap();
            }
            executor.idle().await;
            let began = Instant::now();
            let free = loop {
                if let Some(free) = *seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                {
                    break free;
                }
                assert!(
                    began.elapsed() < Duration::from_secs(5),
                    "the operation is let go of"
                );
                tokio::task::yield_now().await;
            };
            assert_eq!(
                free,
                full - 1,
                "free request slots when the operation was let go of (abandoned: {abandoned})"
            );
        }
    }
}
