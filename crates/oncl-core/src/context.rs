use crate::{ExecutionGrant, OperationPolicy};
use oncl_pki::resource::{Deadline, OperationLease, ResourceScope};
use std::sync::Arc;

/// Process-local, monotonically assigned invocation identifier, unique across engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationId(pub(crate) u64);
impl OperationId {
    pub fn get(self) -> u64 {
        self.0
    }
}
impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Owned, Send operation state, independent of an engine borrow or runtime. Move
/// this value into a worker and capture a separate `Arc<Engine>`. A response or
/// output can retain `lease()` without making a live worker's reservations free.
#[derive(Debug)]
pub struct OperationContext {
    pub(crate) id: OperationId,
    pub(crate) owner: Arc<()>,
    pub(crate) grant: ExecutionGrant,
    pub(crate) policy: OperationPolicy,
    pub(crate) scope: ResourceScope,
    pub(crate) leases: Vec<crate::keys::KeyLease>,
}
impl OperationContext {
    pub fn id(&self) -> OperationId {
        self.id
    }
    pub fn grant(&self) -> &ExecutionGrant {
        &self.grant
    }
    pub fn policy(&self) -> &OperationPolicy {
        &self.policy
    }
    pub fn resources(&mut self) -> &mut ResourceScope {
        &mut self.scope
    }
    pub fn deadline(&self) -> Deadline {
        self.scope.deadline()
    }
    pub fn lease(&self) -> OperationLease {
        self.scope.lease()
    }
}
