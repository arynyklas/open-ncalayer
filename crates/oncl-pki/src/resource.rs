//! Synchronous, runtime-independent resource accounting.
//!
//! One application owns one [`SharedBudget`]. Each admitted operation has its own
//! limits as well; attaching a larger shared budget never enlarges those limits.
//! Reservations precede allocations/writes and keep the root admission lease alive.
//! These counters bound accounted working buffers, not total process RSS or a caller's
//! pre-existing allocations. Blocking `Read`/`Write` implementations must provide their
//! own interruptible I/O: checkpoints cannot preempt an arbitrary synchronous syscall.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

/// Maximum document I/O buffer size, independent of document length.
pub const IO_CHUNK_BYTES: usize = 256 * 1024;

/// Per-operation limits; the same type configures aggregate live resource limits.
#[derive(Clone, Debug)]
pub struct ResourceLimits {
    pub max_in_flight: u64,
    /// Document allowance. Hostile input one byte past it is rejected.
    pub input_bytes: u64,
    /// Signature/envelope bytes. Own signed results (CMS, PDF) may exceed
    /// `input_bytes` by classified container bytes only, never past this value;
    /// formats may narrow it further (PDF: appended revisions, `PdfLimits`).
    /// `output_bytes` should cover input + container + framing.
    pub container_bytes: u64,
    pub framing_bytes: u64,
    pub output_bytes: u64,
    pub memory_bytes: u64,
    pub temp_bytes: u64,
    pub metadata_bytes: u64,
    pub operation_timeout: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 1,
            input_bytes: 1_073_741_824,
            container_bytes: 1_073_741_824,
            framing_bytes: 67_108_864,
            output_bytes: 2_214_592_512,
            memory_bytes: 1_073_741_824,
            temp_bytes: 8_589_934_592,
            metadata_bytes: 67_108_864,
            operation_timeout: Duration::from_secs(300),
        }
    }
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<(), ProcessingError> {
        if self.max_in_flight == 0
            || self.operation_timeout.is_zero()
            || Instant::now().checked_add(self.operation_timeout).is_none()
        {
            return Err(ProcessingError::InvalidLimits);
        }
        Ok(())
    }
}

/// Execution failures, never signature verdicts or parsed error messages.
#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("operation cancelled")]
    Cancelled,
    #[error("operation deadline exceeded")]
    DeadlineExceeded,
    #[error("operation capacity exceeded")]
    CapacityExceeded,
    #[error("input byte limit exceeded")]
    InputLimit,
    #[error("container byte limit exceeded")]
    ContainerLimit,
    #[error("framing byte limit exceeded")]
    FramingLimit,
    #[error("output byte limit exceeded")]
    OutputLimit,
    #[error("live memory limit exceeded")]
    MemoryLimit,
    #[error("temporary disk limit exceeded")]
    TempLimit,
    #[error("metadata limit exceeded")]
    MetadataLimit,
    #[error("invalid resource limits")]
    InvalidLimits,
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
}

/// Cumulative operation byte counts supplied at every checkpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub trait OperationControl: Send + Sync {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError>;
}

/// Monotonic end-to-end deadline, copied without restarting its clock.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn after(timeout: Duration) -> Result<Self, ProcessingError> {
        if timeout.is_zero() {
            return Err(ProcessingError::InvalidLimits);
        }
        Instant::now()
            .checked_add(timeout)
            .map(Self)
            .ok_or(ProcessingError::InvalidLimits)
    }
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.0
    }
    pub fn remaining(&self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }
    pub fn checkpoint(&self) -> Result<(), ProcessingError> {
        if self.is_expired() {
            Err(ProcessingError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
struct Usage {
    in_flight: u64,
    memory: u64,
    temp: u64,
    metadata: u64,
    input: u64,
    input_terminal: bool,
    container: u64,
    framing: u64,
    output: u64,
    wire_input: u64,
    pending_wire: u64,
    pending_owner: Option<Weak<()>>,
}

// No user code runs under these locks. Recovery also keeps Drop non-panicking if
// an unrelated panic poisoned a lock; all mutations are checked before publication.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug)]
pub struct SharedBudget {
    limits: ResourceLimits,
    usage: Mutex<Usage>,
}

impl SharedBudget {
    pub fn new(limits: ResourceLimits) -> Result<Self, ProcessingError> {
        limits.validate()?;
        Ok(Self {
            limits,
            usage: Mutex::new(Usage::default()),
        })
    }

    /// Admit retained host configuration without occupying an operation slot or
    /// creating a Scope/deadline. Metadata also counts as live RAM exactly once.
    /// The configuration owner must retain this reservation with its data.
    pub fn reserve_configuration(
        self: &Arc<Self>,
        direct_memory: u64,
        metadata: u64,
    ) -> Result<ConfigurationReservation, ProcessingError> {
        let mut reservation = ConfigurationReservation {
            budget: self.clone(),
            direct_memory: 0,
            metadata: 0,
        };
        reservation.grow(direct_memory, metadata)?;
        Ok(reservation)
    }

    /// Admit once, before intake. Clones of the returned root lease do not admit again.
    pub fn begin(
        self: &Arc<Self>,
        limits: ResourceLimits,
        control: Arc<dyn OperationControl>,
    ) -> Result<ResourceScope, ProcessingError> {
        limits.validate()?;
        let deadline = Deadline::after(limits.operation_timeout)?;
        let mut usage = lock(&self.usage);
        usage.in_flight = self.next_in_flight(&usage, &limits)?;
        drop(usage);
        Ok(self.scope(limits, deadline, control, true))
    }

    /// Admit an operation that is still only receiving its input and takes no
    /// `max_in_flight` slot yet. Every other budget (memory, temporary disk, metadata,
    /// document, container and framing allowances, the deadline and the control) is
    /// charged exactly as for [`Self::begin`]; only the count of running operations is not.
    /// The host takes the slot with [`ResourceScope::occupy_slot`] before it starts work and
    /// bounds the number of such operations itself.
    pub fn begin_unslotted(
        self: &Arc<Self>,
        limits: ResourceLimits,
        control: Arc<dyn OperationControl>,
    ) -> Result<ResourceScope, ProcessingError> {
        limits.validate()?;
        let deadline = Deadline::after(limits.operation_timeout)?;
        Ok(self.scope(limits, deadline, control, false))
    }

    /// The count after one more slot, or the refusal when `max_in_flight` is reached.
    fn next_in_flight(
        &self,
        usage: &Usage,
        limits: &ResourceLimits,
    ) -> Result<u64, ProcessingError> {
        let count = usage
            .in_flight
            .checked_add(1)
            .ok_or(ProcessingError::CapacityExceeded)?;
        if count > self.limits.max_in_flight || count > limits.max_in_flight {
            return Err(ProcessingError::CapacityExceeded);
        }
        Ok(count)
    }

    fn scope(
        self: &Arc<Self>,
        limits: ResourceLimits,
        deadline: Deadline,
        control: Arc<dyn OperationControl>,
        slot: bool,
    ) -> ResourceScope {
        ResourceScope {
            state: Arc::new(ScopeState {
                root: OperationLease(Arc::new(LeaseInner {
                    budget: self.clone(),
                    deadline,
                    guard: std::sync::OnceLock::new(),
                    slot: std::sync::atomic::AtomicBool::new(slot),
                })),
                limits,
                deadline,
                control,
                usage: Mutex::new(Usage::default()),
            }),
        }
    }
}

/// Global host-configuration memory/metadata ownership, not operation authority.
/// No input/output credits, active slot, Scope, deadline, or detachable data are
/// exposed. Failed growth changes neither owner nor aggregate counters.
pub struct ConfigurationReservation {
    budget: Arc<SharedBudget>,
    direct_memory: u64,
    metadata: u64,
}
impl ConfigurationReservation {
    pub fn grow(&mut self, direct_memory: u64, metadata: u64) -> Result<(), ProcessingError> {
        let next_direct = self
            .direct_memory
            .checked_add(direct_memory)
            .ok_or(ProcessingError::MemoryLimit)?;
        let next_metadata = self
            .metadata
            .checked_add(metadata)
            .ok_or(ProcessingError::MetadataLimit)?;
        let memory = direct_memory
            .checked_add(metadata)
            .ok_or(ProcessingError::MemoryLimit)?;
        let mut usage = lock(&self.budget.usage);
        let global_memory = usage
            .memory
            .checked_add(memory)
            .ok_or(ProcessingError::MemoryLimit)?;
        let global_metadata = usage
            .metadata
            .checked_add(metadata)
            .ok_or(ProcessingError::MetadataLimit)?;
        if global_metadata > self.budget.limits.metadata_bytes {
            return Err(ProcessingError::MetadataLimit);
        }
        if global_memory > self.budget.limits.memory_bytes {
            return Err(ProcessingError::MemoryLimit);
        }
        usage.memory = global_memory;
        usage.metadata = global_metadata;
        self.direct_memory = next_direct;
        self.metadata = next_metadata;
        Ok(())
    }
}
impl std::fmt::Debug for ConfigurationReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigurationReservation")
            .field("direct_memory", &self.direct_memory)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}
impl Drop for ConfigurationReservation {
    fn drop(&mut self) {
        let mut usage = lock(&self.budget.usage);
        if let Some(memory) = self.direct_memory.checked_add(self.metadata)
            && let Some(global_memory) = usage.memory.checked_sub(memory)
            && let Some(global_metadata) = usage.metadata.checked_sub(self.metadata)
        {
            usage.memory = global_memory;
            usage.metadata = global_metadata;
        }
    }
}

#[derive(Debug)]
struct LeaseInner {
    budget: Arc<SharedBudget>,
    deadline: Deadline,
    /// Dropped with the lease, i.e. when the last owner of the operation lets go.
    guard: std::sync::OnceLock<Box<dyn std::any::Any + Send + Sync>>,
    /// Whether this operation holds one of the `max_in_flight` slots. Changed only under the
    /// budget's usage lock.
    slot: std::sync::atomic::AtomicBool,
}
impl Drop for LeaseInner {
    fn drop(&mut self) {
        let mut usage = lock(&self.budget.usage);
        // Exactly one decrement for each slot taken, none for an operation that never took one.
        if self.slot.load(std::sync::atomic::Ordering::Acquire)
            && let Some(remaining) = usage.in_flight.checked_sub(1)
        {
            usage.in_flight = remaining;
        }
    }
}

/// Retain in workers, pending responses and artifacts until actual completion.
#[derive(Clone, Debug)]
pub struct OperationLease(Arc<LeaseInner>);
impl OperationLease {
    pub fn deadline(&self) -> Deadline {
        self.0.deadline
    }
    /// Ties `guard` to the operation: it is dropped when the last owner of this lease (the
    /// context, a worker that outlives it, a pending response or artifact) lets go, not
    /// earlier. A host uses it to count the operation as running until native work has really
    /// returned. Only the first guard is kept; `false` (and `guard` dropped at once) if one
    /// is set already. Without a guard nothing changes.
    pub fn attach_guard(&self, guard: Box<dyn std::any::Any + Send + Sync>) -> bool {
        self.0.guard.set(guard).is_ok()
    }
    /// Non-owning identity probe. It keeps no permit, buffer or authority alive
    /// and cannot be upgraded back into a lease.
    pub fn downgrade(&self) -> WeakOperationLease {
        WeakOperationLease(Arc::downgrade(&self.0))
    }
}
/// Observes only whether every owner of an operation (context, workers,
/// responses, artifacts) has been dropped.
#[derive(Clone, Debug)]
pub struct WeakOperationLease(std::sync::Weak<LeaseInner>);
impl WeakOperationLease {
    pub fn is_live(&self) -> bool {
        self.0.strong_count() > 0
    }
}

struct ScopeState {
    root: OperationLease,
    limits: ResourceLimits,
    deadline: Deadline,
    control: Arc<dyn OperationControl>,
    usage: Mutex<Usage>,
}

/// Owned operation accounting. Internal artifact handles share this exact state,
/// not a fresh quota, and all live reservations retain the operation admission.
pub struct ResourceScope {
    state: Arc<ScopeState>,
}

impl std::fmt::Debug for ResourceScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceScope")
            .field("limits", &self.state.limits)
            .field("deadline", &self.state.deadline)
            .finish_non_exhaustive()
    }
}

impl ResourceScope {
    pub fn lease(&self) -> OperationLease {
        self.state.root.clone()
    }
    /// Takes the `max_in_flight` slot of an operation admitted with
    /// [`SharedBudget::begin_unslotted`]; `Ok` at once when the operation already holds one
    /// (every operation admitted with [`SharedBudget::begin`] does). `CapacityExceeded` when
    /// every slot is taken: nothing changes then and the call may be repeated. The slot is
    /// released when the last owner of the operation lets go, like the one of `begin`.
    pub fn occupy_slot(&self) -> Result<(), ProcessingError> {
        self.checkpoint()?;
        let lease = &self.state.root.0;
        let mut usage = lock(&lease.budget.usage);
        if lease.slot.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        usage.in_flight = lease.budget.next_in_flight(&usage, &self.state.limits)?;
        lease.slot.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    /// Whether this operation holds a `max_in_flight` slot.
    pub fn holds_slot(&self) -> bool {
        self.state
            .root
            .0
            .slot
            .load(std::sync::atomic::Ordering::Acquire)
    }
    /// Share live checkpoint state without a new quota, stale progress or cycle.
    pub fn operation_control(&self) -> Arc<dyn OperationControl> {
        struct LiveControl(ResourceScope);
        impl OperationControl for LiveControl {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                self.0.checkpoint()
            }
        }
        Arc::new(LiveControl(self.retain()))
    }
    pub fn deadline(&self) -> Deadline {
        self.state.deadline
    }
    pub fn limits(&self) -> &ResourceLimits {
        &self.state.limits
    }
    pub fn progress(&self) -> Progress {
        let usage = lock(&self.state.usage);
        Progress {
            bytes_in: usage.wire_input,
            bytes_out: usage.output,
        }
    }
    pub fn checkpoint(&self) -> Result<(), ProcessingError> {
        self.state.deadline.checkpoint()?;
        self.state.control.checkpoint(self.progress())?;
        self.state.deadline.checkpoint()
    }
    /// Identity of the complete quota/control/deadline state, not merely its
    /// application budget. Used only to deduplicate nested scoped I/O charges.
    pub fn same_operation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
    pub(crate) fn retain(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
    /// Another handle to this exact operation, sharing all cumulative quotas,
    /// cancellation, deadline and root lifetime. Never grants fresh capacity.
    /// Aliases belong to one invocation, not a pool for unrelated requests.
    pub fn shared_view(&self) -> Self {
        self.retain()
    }
    pub fn reserve_memory(&self, bytes: u64) -> Result<ResourceReservation, ProcessingError> {
        self.reserve(Kind::Memory, bytes)
    }
    pub fn reserve_temp(&self, bytes: u64) -> Result<ResourceReservation, ProcessingError> {
        self.reserve(Kind::Temp, bytes)
    }
    pub fn reserve_metadata(&self, bytes: u64) -> Result<ResourceReservation, ProcessingError> {
        self.reserve(Kind::Metadata, bytes)
    }
    fn reserve(&self, kind: Kind, bytes: u64) -> Result<ResourceReservation, ProcessingError> {
        let mut reservation = ResourceReservation {
            state: self.state.clone(),
            kind,
            bytes: 0,
        };
        reservation.grow(bytes)?;
        Ok(reservation)
    }
    pub(crate) fn available_memory(&self) -> u64 {
        let budget = &self.state.root.0.budget;
        let global = lock(&budget.usage);
        let local = lock(&self.state.usage);
        (budget.limits.memory_bytes - global.memory)
            .min(self.state.limits.memory_bytes - local.memory)
    }
    pub fn input_remaining(&self) -> u64 {
        let usage = lock(&self.state.usage);
        self.state
            .limits
            .input_bytes
            .saturating_sub(usage.input)
            .saturating_sub(usage.pending_wire)
    }
    /// Remaining container consumption, including capacity needed by pending
    /// wire. This read-only value never grants or resets an allowance.
    pub fn container_remaining(&self) -> u64 {
        let usage = lock(&self.state.usage);
        let document = self.state.limits.input_bytes.saturating_sub(usage.input);
        self.state
            .limits
            .container_bytes
            .saturating_sub(usage.container)
            .saturating_sub(usage.pending_wire.saturating_sub(document))
    }
    pub(crate) fn check_input(&self) -> Result<(), ProcessingError> {
        if lock(&self.state.usage).input_terminal {
            Err(ProcessingError::InputLimit)
        } else {
            Ok(())
        }
    }
    pub(crate) fn input_request(&self, capacity: usize) -> Result<usize, ProcessingError> {
        let usage = lock(&self.state.usage);
        if usage.input_terminal {
            return Err(ProcessingError::InputLimit);
        }
        // Never consume a byte that the public u64 progress cannot represent.
        let representable = u64::MAX - usage.wire_input;
        if representable == 0 {
            return Err(ProcessingError::InputLimit);
        }
        Ok(self
            .state
            .limits
            .input_bytes
            .saturating_sub(usage.input)
            .saturating_sub(usage.pending_wire)
            .saturating_add(1)
            .min(representable)
            .min(capacity as u64) as usize)
    }
    /// Streaming wire intake whose envelope bytes are classified as container
    /// while they are parsed. Document bytes stay bound by `input_bytes`; only
    /// bytes the parser later accounts as container may exceed it, and never past
    /// `container_bytes`. Pair every chunk with [`Self::settle_wire`].
    pub(crate) fn wire_request(&self, capacity: usize) -> Result<usize, ProcessingError> {
        let usage = lock(&self.state.usage);
        if usage.input_terminal || usage.pending_owner.is_some() {
            return Err(ProcessingError::InputLimit);
        }
        let representable = u64::MAX - usage.wire_input;
        if representable == 0 {
            return Err(ProcessingError::InputLimit);
        }
        let document = self.state.limits.input_bytes.saturating_sub(usage.input);
        let container = self
            .state
            .limits
            .container_bytes
            .saturating_sub(usage.container);
        Ok((u128::from(document) + u128::from(container) + 1)
            .saturating_sub(u128::from(usage.pending_wire))
            .min(u128::from(representable))
            .min(capacity.max(1) as u128) as usize)
    }
    pub(crate) fn consumed_wire(&self, bytes: u64) -> Result<(), ProcessingError> {
        let mut usage = lock(&self.state.usage);
        let wire = usage.wire_input.checked_add(bytes);
        let pending = usage.pending_wire.checked_add(bytes);
        let (Some(wire), Some(pending)) = (wire, pending) else {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        };
        usage.wire_input = wire;
        usage.pending_wire = pending;
        let document = self.state.limits.input_bytes.saturating_sub(usage.input);
        let container = self
            .state
            .limits
            .container_bytes
            .saturating_sub(usage.container);
        if u128::from(pending) > u128::from(document) + u128::from(container) {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        }
        Ok(())
    }
    /// Resolve all pending wire: `container` bytes were already accounted via
    /// `account_container`; the remaining `document` bytes are charged as input.
    pub(crate) fn settle_wire(&self, document: u64, container: u64) -> Result<(), ProcessingError> {
        let mut usage = lock(&self.state.usage);
        if document.checked_add(container) != Some(usage.pending_wire) {
            usage.input_terminal = true;
            return Err(ProcessingError::InvalidInput("wire classification extent"));
        }
        match usage
            .input
            .checked_add(document)
            .filter(|n| *n <= self.state.limits.input_bytes)
        {
            Some(next) => {
                usage.input = next;
                usage.pending_wire = 0;
                Ok(())
            }
            None => {
                usage.input_terminal = true;
                Err(ProcessingError::InputLimit)
            }
        }
    }
    /// An actually over-consumed format-bound input is terminal for this same
    /// operation, even when the format cap is below the resource-wide cap.
    pub(crate) fn terminate_input_limit(&self) {
        lock(&self.state.usage).input_terminal = true;
    }
    /// Unlike pre-admission accounting, an actual successful read is irrevocable.
    /// Do not call cancellation/deadline code until its bytes have been recorded.
    pub(crate) fn consumed_input(&self, bytes: u64) -> Result<(), ProcessingError> {
        let mut usage = lock(&self.state.usage);
        let Some(next) = usage.input.checked_add(bytes) else {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        };
        usage.input = next;
        usage.wire_input = match usage.wire_input.checked_add(bytes) {
            Some(next) => next,
            None => {
                usage.input_terminal = true;
                return Err(ProcessingError::InputLimit);
            }
        };
        if u128::from(next) + u128::from(usage.pending_wire)
            > u128::from(self.state.limits.input_bytes)
        {
            usage.input_terminal = true;
        }
        if usage.input_terminal {
            Err(ProcessingError::InputLimit)
        } else {
            Ok(())
        }
    }
    pub fn account_input(&self, bytes: u64) -> Result<(), ProcessingError> {
        self.account(Count::Input, bytes)
    }
    pub fn account_container(&self, bytes: u64) -> Result<(), ProcessingError> {
        self.account(Count::Container, bytes)
    }
    pub fn account_framing(&self, bytes: u64) -> Result<(), ProcessingError> {
        self.account(Count::Framing, bytes)
    }
    /// Non-debiting preflight only, not a reservation or an output/replay permit.
    /// Actual writers must still call account_output under the original scope.
    pub fn check_output_capacity(&self, bytes: u64) -> Result<(), ProcessingError> {
        self.checkpoint()?;
        lock(&self.state.usage)
            .output
            .checked_add(bytes)
            .filter(|n| *n <= self.state.limits.output_bytes)
            .map(|_| ())
            .ok_or(ProcessingError::OutputLimit)
    }
    pub fn account_output(&self, bytes: u64) -> Result<(), ProcessingError> {
        self.account(Count::Output, bytes)
    }
    pub(crate) fn begin_signed_input(&self, owner: &Arc<()>) -> Result<(), ProcessingError> {
        self.checkpoint()?;
        let mut usage = lock(&self.state.usage);
        if usage.input_terminal {
            return Err(ProcessingError::InputLimit);
        }
        if usage.pending_owner.is_some() {
            return Err(ProcessingError::CapacityExceeded);
        }
        if usage.pending_wire != 0 {
            return Err(ProcessingError::InvalidInput("unresolved wire intake"));
        }
        usage.pending_owner = Some(Arc::downgrade(owner));
        Ok(())
    }
    fn signed_owner(usage: &Usage, owner: &Arc<()>) -> bool {
        usage
            .pending_owner
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|expected| Arc::ptr_eq(&expected, owner))
    }
    fn signed_remaining(&self, usage: &Usage, maximum: u64) -> u128 {
        let document = self.state.limits.input_bytes.saturating_sub(usage.input);
        let container = self
            .state
            .limits
            .container_bytes
            .saturating_sub(usage.container)
            .min(maximum);
        (u128::from(document) + u128::from(container))
            .saturating_sub(u128::from(usage.pending_wire))
    }
    pub(crate) fn signed_input_request(
        &self,
        owner: &Arc<()>,
        maximum: u64,
        capacity: usize,
    ) -> Result<usize, ProcessingError> {
        let mut usage = lock(&self.state.usage);
        if usage.input_terminal {
            return Err(ProcessingError::InputLimit);
        }
        if !Self::signed_owner(&usage, owner) {
            return Err(ProcessingError::InvalidInput("foreign pending intake"));
        }
        let representable = u64::MAX - usage.wire_input;
        if representable == 0 {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        }
        Ok((self.signed_remaining(&usage, maximum) + 1)
            .min(u128::from(representable))
            .min(capacity.max(1) as u128) as usize)
    }
    pub(crate) fn consumed_signed_input(
        &self,
        owner: &Arc<()>,
        maximum: u64,
        bytes: u64,
    ) -> Result<(), ProcessingError> {
        let mut usage = lock(&self.state.usage);
        if usage.input_terminal {
            return Err(ProcessingError::InputLimit);
        }
        if !Self::signed_owner(&usage, owner) {
            return Err(ProcessingError::InvalidInput("foreign pending intake"));
        }
        let remaining = self.signed_remaining(&usage, maximum);
        let wire = usage.wire_input.checked_add(bytes);
        let pending = usage.pending_wire.checked_add(bytes);
        let (Some(wire), Some(pending)) = (wire, pending) else {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        };
        usage.wire_input = wire;
        usage.pending_wire = pending;
        if u128::from(bytes) > remaining {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        }
        Ok(())
    }
    pub(crate) fn classify_signed_input(
        &self,
        owner: &Arc<()>,
        wire: u64,
        document: u64,
        container: u64,
    ) -> Result<(), ProcessingError> {
        self.checkpoint()?;
        let mut usage = lock(&self.state.usage);
        if usage.input_terminal {
            return Err(ProcessingError::InputLimit);
        }
        if !Self::signed_owner(&usage, owner)
            || usage.pending_wire != wire
            || document.checked_add(container) != Some(wire)
        {
            usage.input_terminal = true;
            return Err(ProcessingError::InvalidInput(
                "pending classification extent/owner",
            ));
        }
        let next_document = usage
            .input
            .checked_add(document)
            .filter(|n| *n <= self.state.limits.input_bytes);
        let next_container = usage
            .container
            .checked_add(container)
            .filter(|n| *n <= self.state.limits.container_bytes);
        let Some(next_document) = next_document else {
            usage.input_terminal = true;
            return Err(ProcessingError::InputLimit);
        };
        let Some(next_container) = next_container else {
            usage.input_terminal = true;
            return Err(ProcessingError::ContainerLimit);
        };
        usage.input = next_document;
        usage.container = next_container;
        // Transfer unassigned capacity, never refund historical wire or input.
        usage.pending_wire = 0;
        usage.pending_owner = None;
        Ok(())
    }
    pub(crate) fn abandon_signed_input(&self, owner: &Arc<()>) {
        let mut usage = lock(&self.state.usage);
        if Self::signed_owner(&usage, owner) {
            usage.input_terminal = true;
        }
    }
    fn account(&self, count: Count, bytes: u64) -> Result<(), ProcessingError> {
        self.checkpoint()?;
        let mut usage = lock(&self.state.usage);
        match count {
            Count::Input => {
                if usage.input_terminal {
                    return Err(ProcessingError::InputLimit);
                }
                let next = usage
                    .input
                    .checked_add(bytes)
                    .filter(|n| {
                        u128::from(*n) + u128::from(usage.pending_wire)
                            <= u128::from(self.state.limits.input_bytes)
                    })
                    .ok_or(ProcessingError::InputLimit)?;
                let wire = usage
                    .wire_input
                    .checked_add(bytes)
                    .ok_or(ProcessingError::InputLimit)?;
                usage.input = next;
                usage.wire_input = wire;
            }
            Count::Container => {
                let document = self.state.limits.input_bytes.saturating_sub(usage.input);
                let next = usage
                    .container
                    .checked_add(bytes)
                    .filter(|n| *n <= self.state.limits.container_bytes)
                    .filter(|n| {
                        u128::from(usage.pending_wire)
                            <= u128::from(document)
                                + u128::from(self.state.limits.container_bytes - *n)
                    })
                    .ok_or(ProcessingError::ContainerLimit)?;
                usage.container = next;
            }
            Count::Framing => {
                usage.framing = usage
                    .framing
                    .checked_add(bytes)
                    .filter(|n| *n <= self.state.limits.framing_bytes)
                    .ok_or(ProcessingError::FramingLimit)?
            }
            Count::Output => {
                usage.output = usage
                    .output
                    .checked_add(bytes)
                    .filter(|n| *n <= self.state.limits.output_bytes)
                    .ok_or(ProcessingError::OutputLimit)?
            }
        }
        Ok(())
    }
}

enum Count {
    Input,
    Container,
    Framing,
    Output,
}
#[derive(Clone, Copy)]
enum Kind {
    Memory,
    Temp,
    Metadata,
}
impl Kind {
    fn counter(self, usage: &mut Usage) -> &mut u64 {
        match self {
            Self::Memory => &mut usage.memory,
            Self::Temp => &mut usage.temp,
            Self::Metadata => &mut usage.metadata,
        }
    }
    fn limit(self, limits: &ResourceLimits) -> u64 {
        match self {
            Self::Memory => limits.memory_bytes,
            Self::Temp => limits.temp_bytes,
            Self::Metadata => limits.metadata_bytes,
        }
    }
    fn error(self) -> ProcessingError {
        match self {
            Self::Memory => ProcessingError::MemoryLimit,
            Self::Temp => ProcessingError::TempLimit,
            Self::Metadata => ProcessingError::MetadataLimit,
        }
    }
}

/// A checked live reservation. Rejection never changes either counter. Drop
/// releases both counters even after cancellation/deadline/context destruction.
pub struct ResourceReservation {
    state: Arc<ScopeState>,
    kind: Kind,
    bytes: u64,
}
impl ResourceReservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn grow(&mut self, bytes: u64) -> Result<(), ProcessingError> {
        let scope = ResourceScope {
            state: self.state.clone(),
        };
        scope.checkpoint()?;
        let budget = &self.state.root.0.budget;
        // Every acquisition/release uses global -> local lock order.
        let mut global = lock(&budget.usage);
        let mut local = lock(&self.state.usage);
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| self.kind.error())?;
        let g = self
            .kind
            .counter(&mut global)
            .checked_add(bytes)
            .filter(|n| *n <= self.kind.limit(&budget.limits))
            .ok_or_else(|| self.kind.error())?;
        let l = self
            .kind
            .counter(&mut local)
            .checked_add(bytes)
            .filter(|n| *n <= self.kind.limit(&self.state.limits))
            .ok_or_else(|| self.kind.error())?;
        // Metadata is a separately capped subset of live memory, not extra RAM
        // that becomes free merely because it has a different counter.
        let memory = if matches!(self.kind, Kind::Metadata) {
            Some((
                global
                    .memory
                    .checked_add(bytes)
                    .filter(|n| *n <= budget.limits.memory_bytes)
                    .ok_or(ProcessingError::MemoryLimit)?,
                local
                    .memory
                    .checked_add(bytes)
                    .filter(|n| *n <= self.state.limits.memory_bytes)
                    .ok_or(ProcessingError::MemoryLimit)?,
            ))
        } else {
            None
        };
        *self.kind.counter(&mut global) = g;
        *self.kind.counter(&mut local) = l;
        if let Some((g, l)) = memory {
            global.memory = g;
            local.memory = l;
        }
        self.bytes = total;
        Ok(())
    }
    /// Release part of a reservation; over-release is rejected without mutation.
    pub fn shrink(&mut self, bytes: u64) -> Result<(), ProcessingError> {
        let remaining = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| self.kind.error())?;
        let budget = &self.state.root.0.budget;
        let mut global = lock(&budget.usage);
        let mut local = lock(&self.state.usage);
        let g = self
            .kind
            .counter(&mut global)
            .checked_sub(bytes)
            .ok_or_else(|| self.kind.error())?;
        let l = self
            .kind
            .counter(&mut local)
            .checked_sub(bytes)
            .ok_or_else(|| self.kind.error())?;
        let memory = if matches!(self.kind, Kind::Metadata) {
            Some((
                global
                    .memory
                    .checked_sub(bytes)
                    .ok_or(ProcessingError::MemoryLimit)?,
                local
                    .memory
                    .checked_sub(bytes)
                    .ok_or(ProcessingError::MemoryLimit)?,
            ))
        } else {
            None
        };
        *self.kind.counter(&mut global) = g;
        *self.kind.counter(&mut local) = l;
        if let Some((g, l)) = memory {
            global.memory = g;
            local.memory = l;
        }
        self.bytes = remaining;
        Ok(())
    }
}
impl Drop for ResourceReservation {
    fn drop(&mut self) {
        let _ = self.shrink(self.bytes);
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Flag(Arc<AtomicBool>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_guard_lives_until_the_last_owner_of_the_lease_lets_go() {
        let budget = Arc::new(SharedBudget::new(ResourceLimits::default()).unwrap());
        struct C;
        impl OperationControl for C {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                Ok(())
            }
        }
        let scope = budget
            .begin(ResourceLimits::default(), Arc::new(C))
            .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let lease = scope.lease();
        assert!(lease.attach_guard(Box::new(Flag(Arc::clone(&dropped)))));
        assert!(
            !lease.attach_guard(Box::new(())),
            "only the first guard is kept"
        );
        drop(scope);
        assert!(
            !dropped.load(Ordering::SeqCst),
            "a worker still owns the lease"
        );
        drop(lease);
        assert!(dropped.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod default_limit_tests {
    use super::*;

    struct Open;
    impl OperationControl for Open {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }

    fn scope() -> ResourceScope {
        let limits = ResourceLimits::default();
        Arc::new(SharedBudget::new(limits.clone()).unwrap())
            .begin(limits, Arc::new(Open))
            .unwrap()
    }

    #[test]
    fn the_default_guarantees_one_gibibyte_and_refuses_one_byte_more() {
        const GIB: u64 = 1_073_741_824;
        let scope = scope();
        scope.account_input(GIB).unwrap();
        assert!(matches!(
            scope.account_input(1),
            Err(ProcessingError::InputLimit)
        ));
        let scope = self::scope();
        assert!(matches!(
            scope.account_input(GIB + 1),
            Err(ProcessingError::InputLimit)
        ));
    }

    #[test]
    fn the_default_output_ceiling_covers_input_container_and_framing() {
        let limits = ResourceLimits::default();
        assert_eq!(
            limits.output_bytes,
            limits.input_bytes + limits.container_bytes + limits.framing_bytes
        );
        let scope = scope();
        scope.check_output_capacity(limits.output_bytes).unwrap();
        assert!(matches!(
            scope.check_output_capacity(limits.output_bytes + 1),
            Err(ProcessingError::OutputLimit)
        ));
        assert!(limits.input_bytes <= 1_073_741_824);
        assert_eq!(limits.temp_bytes, 8_589_934_592);
    }
}
