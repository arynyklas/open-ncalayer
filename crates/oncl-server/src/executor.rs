//! Admission is finite BEFORE spawn_blocking. Cancellation drops the receiver,
//! not a running native closure or its worker/resource permits.
use oncl_core::OperationContext;
use oncl_pki::resource::{OperationControl, ProcessingError, Progress};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
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
    receiver: oneshot::Receiver<Result<WorkOutput<T>, ProcessingError>>,
    abandoned: Arc<Cancellation>,
    deadline: oncl_pki::resource::Deadline,
}
impl<T> WorkHandle<T> {
    pub async fn wait(mut self) -> Result<WorkOutput<T>, ProcessingError> {
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
impl BoundedExecutor {
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
    ) -> Result<WorkHandle<T>, ProcessingError>
    where
        T: Send + 'static,
        F: FnOnce(&mut OperationContext) -> Result<T, ProcessingError> + Send + 'static,
    {
        ctx.resources().checkpoint()?;
        let slot = self
            .shared
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ProcessingError::CapacityExceeded)?;
        let active = Active {
            shared: self.shared.clone(),
            slot: Some(slot),
        };
        let immediate = self.shared.workers.clone().try_acquire_owned().ok();
        let waiting = if immediate.is_none() {
            let previous = self.shared.waiting.fetch_add(1, Ordering::AcqRel);
            if previous >= self.shared.config.queue_capacity {
                self.shared.waiting.fetch_sub(1, Ordering::AcqRel);
                return Err(ProcessingError::CapacityExceeded);
            }
            Some(Waiting(self.shared.clone()))
        } else {
            None
        };
        let (sender, receiver) = oneshot::channel();
        let abandoned = Arc::new(Cancellation::new());
        let stop = abandoned.clone();
        let deadline = ctx.deadline();
        let shared = self.shared.clone();
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
                            drop(waiting);
                            drop(ctx);
                            drop(active);
                            let _ = sender.send(Err(error));
                            return;
                        }
                    }
                }
            };
            drop(waiting);
            if let Err(error) = ctx
                .resources()
                .checkpoint()
                .and_then(|_| stop.checkpoint(Progress::default()))
            {
                drop(ctx);
                drop(worker);
                drop(active);
                let _ = sender.send(Err(error));
                return;
            }
            shared.running.fetch_add(1, Ordering::AcqRel);
            let running = Running(shared);
            // Worker permit, admission slot, context and reservations are INSIDE
            // the real closure, never merely inside a cancellable async waiter.
            tokio::task::spawn_blocking(move || {
                let _active = active;
                let _worker = worker;
                let _running = running;
                let result = work(&mut ctx).map(|value| WorkOutput {
                    value,
                    context: ctx,
                });
                let _ = sender.send(result);
            });
        });
        Ok(WorkHandle {
            receiver,
            abandoned,
            deadline,
        })
    }
}
