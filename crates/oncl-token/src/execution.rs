//! Bounded admission by actual reader. PC/SC transactions, not this registry,
//! remain the canonical APDU exclusion/session/reset mechanism.
use crate::{
    TokenError,
    backend::{Backend, BackendError, Connection, Protocol, ReaderState},
};
use oncl_pki::{
    key::{AppliedState, KeyExecutionError, KeyFailureKind},
    resource::{OperationControl, OperationLease, Progress},
};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenDeviceId(Arc<str>);
impl TokenDeviceId {
    pub fn new(reader: impl Into<String>) -> Result<Self, TokenError> {
        let reader = reader.into();
        if reader.is_empty() || reader.trim() != reader || reader.contains('\0') {
            return Err(TokenError::NoDevice);
        }
        Ok(Self(Arc::from(reader)))
    }
    pub fn reader(&self) -> &str {
        &self.0
    }
}
#[derive(Default)]
struct Device {
    running: bool,
    waiting: usize,
}
pub struct TokenGateRegistry {
    max_devices: usize,
    max_waiters: usize,
    devices: Mutex<HashMap<TokenDeviceId, Device>>,
    changed: Condvar,
}
impl TokenGateRegistry {
    pub fn new(max_devices: usize, max_waiters_per_device: usize) -> Result<Self, TokenError> {
        if max_devices == 0 {
            return Err(TokenError::Malformed("zero token device capacity".into()));
        }
        Ok(Self {
            max_devices,
            max_waiters: max_waiters_per_device,
            devices: Mutex::new(HashMap::new()),
            changed: Condvar::new(),
        })
    }
    fn acquire(self: &Arc<Self>, execution: &TokenExecution) -> Result<Permit, BackendError> {
        execution.checkpoint(AppliedState::NotApplied)?;
        let mut queued = false;
        loop {
            if let Err(error) = execution.checkpoint(AppliedState::NotApplied) {
                if queued {
                    self.remove_waiter(&execution.device);
                }
                return Err(error);
            }
            let mut devices = self
                .devices
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !devices.contains_key(&execution.device) && devices.len() == self.max_devices {
                return Err(capacity());
            }
            let state = devices.entry(execution.device.clone()).or_default();
            if !state.running {
                state.running = true;
                if queued {
                    state.waiting -= 1;
                }
                return Ok(Permit {
                    registry: self.clone(),
                    device: execution.device.clone(),
                });
            }
            if !queued {
                if state.waiting >= self.max_waiters {
                    return Err(capacity());
                }
                state.waiting += 1;
                queued = true;
            }
            // Periodic checkpoints honor host cancellation too; no unbounded blocked
            // native threads are created while waiting for this admission slot.
            let wait = execution
                .root
                .deadline()
                .remaining()
                .min(Duration::from_millis(20));
            let (guard, _) = self
                .changed
                .wait_timeout(devices, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            drop(guard);
        }
    }
    fn remove_waiter(&self, id: &TokenDeviceId) {
        let mut devices = self
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = devices.get_mut(id) {
            state.waiting -= 1;
            if !state.running && state.waiting == 0 {
                devices.remove(id);
            }
        }
    }
}
fn capacity() -> BackendError {
    BackendError::Execution(KeyExecutionError {
        kind: KeyFailureKind::CapacityExceeded,
        applied: AppliedState::NotApplied,
    })
}
struct Permit {
    registry: Arc<TokenGateRegistry>,
    device: TokenDeviceId,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut devices = self
            .registry
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = devices.get_mut(&self.device) {
            state.running = false;
            if state.waiting == 0 {
                devices.remove(&self.device);
            }
        }
        drop(devices);
        self.registry.changed.notify_all();
    }
}
/// Shares the original root and live resource-control adapter. Not a new quota.
pub struct TokenExecution {
    pub(crate) device: TokenDeviceId,
    root: OperationLease,
    control: Arc<dyn OperationControl>,
    registry: Arc<TokenGateRegistry>,
}
impl TokenExecution {
    pub fn new(
        device: TokenDeviceId,
        root: OperationLease,
        control: Arc<dyn OperationControl>,
        registry: Arc<TokenGateRegistry>,
    ) -> Self {
        Self {
            device,
            root,
            control,
            registry,
        }
    }
    fn checkpoint(&self, applied: AppliedState) -> Result<(), BackendError> {
        self.root
            .deadline()
            .checkpoint()
            .and_then(|_| self.control.checkpoint(Progress::default()))
            .and_then(|_| self.root.deadline().checkpoint())
            .map_err(|error| {
                BackendError::Execution(KeyExecutionError::processing(&error, applied))
            })
    }
}
pub(crate) struct ScopedBackend {
    pub inner: Arc<dyn Backend>,
    pub execution: Arc<TokenExecution>,
}
impl Backend for ScopedBackend {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        self.inner.readers()
    }
    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        if reader != self.execution.device.reader() {
            return Err(BackendError::UnknownReader);
        }
        let permit = self.execution.registry.acquire(&self.execution)?;
        let inner = self.inner.connect(reader)?;
        Ok(Box::new(ScopedConnection {
            inner,
            execution: self.execution.clone(),
            _permit: permit,
            private: false,
            applied: AppliedState::NotApplied,
        }))
    }
}
struct ScopedConnection {
    inner: Box<dyn Connection>,
    execution: Arc<TokenExecution>,
    _permit: Permit,
    private: bool,
    applied: AppliedState,
}
impl Connection for ScopedConnection {
    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }
    fn atr(&self) -> &[u8] {
        self.inner.atr()
    }
    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        self.execution.checkpoint(self.applied)?;
        self.inner.begin_transaction()?; // may block in native code: permit/root remain owned
        if let Err(error) = self.execution.checkpoint(self.applied) {
            let _ = self.inner.end_transaction();
            return Err(error);
        }
        Ok(())
    }
    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.inner.end_transaction()
    }
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.execution.checkpoint(self.applied)?;
        let previous = self.applied;
        if self.private {
            self.applied = AppliedState::Unknown;
        }
        self.inner.transmit(apdu).map_err(|error| {
            match error {
                BackendError::Execution(mut error) => {
                    // An underlying structured NotApplied can prove this call
                    // never dispatched. Retain earlier uncertainty, not merely
                    // our speculative mark immediately before delegation.
                    error.applied = error.applied.combine(previous);
                    self.applied = error.applied;
                    BackendError::Execution(error)
                }
                BackendError::Reset if !self.private => BackendError::Reset,
                BackendError::NoService
                | BackendError::NoReaders
                | BackendError::UnknownReader
                | BackendError::NoCard
                | BackendError::Removed
                | BackendError::Reset
                | BackendError::Sharing
                | BackendError::Failed(_) => BackendError::Execution(KeyExecutionError {
                    kind: KeyFailureKind::Backend,
                    applied: self.applied,
                }),
            }
        })
    }
    fn reset_on_disconnect(&mut self) {
        self.inner.reset_on_disconnect();
    }
    fn begin_private_operation(&mut self) {
        self.private = true;
    }
}
