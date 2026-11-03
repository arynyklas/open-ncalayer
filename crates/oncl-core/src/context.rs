use crate::{ExecutionGrant, OperationError, OperationPolicy};
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
    pub(crate) private_use_stopped: std::sync::atomic::AtomicBool,
    pub(crate) batch_item: Option<crate::keys::BatchItemOrdinal>,
    pub(crate) borrowed_replay: Option<crate::batch::BorrowedReplay>,
    #[cfg(feature = "plugins")]
    pub(crate) plugin_network: Option<crate::plugins::InvocationHttpBudget>,
    #[cfg(feature = "plugins")]
    pub(crate) plugin_network_budget: Option<crate::plugins::InvocationHttpBudget>,
}
impl OperationContext {
    pub(crate) fn account_borrowed(
        &self,
        input: &[u8],
        detached: Option<&[u8]>,
    ) -> Result<(), OperationError> {
        if self
            .borrowed_replay
            .as_ref()
            .is_some_and(|proof| proof.matches(input, detached, &self.scope))
        {
            self.scope.checkpoint()?;
            return Ok(());
        }
        self.scope.account_input(
            (input.len() as u64)
                .checked_add(detached.map_or(0, |d| d.len() as u64))
                .ok_or(oncl_pki::resource::ProcessingError::InputLimit)?,
        )?;
        Ok(())
    }
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
    pub(crate) fn http<'a>(&self, inner: &'a dyn oncl_pki::http::HttpTransport) -> ContextHttp<'a> {
        ContextHttp {
            inner,
            #[cfg(feature = "plugins")]
            budget: self.plugin_network.clone(),
        }
    }
    pub(crate) fn network_status(&self) -> Result<(), OperationError> {
        #[cfg(feature = "plugins")]
        if let Some(budget) = &self.plugin_network {
            budget.status()?;
        }
        Ok(())
    }
}

/// Delegates routing, pins and response admission without changing the original
/// resource scope or introducing another transport budget.
pub(crate) struct ContextHttp<'a> {
    inner: &'a dyn oncl_pki::http::HttpTransport,
    #[cfg(feature = "plugins")]
    budget: Option<crate::plugins::InvocationHttpBudget>,
}
impl ContextHttp<'_> {
    fn take(&self) -> Result<(), oncl_pki::http::HttpError> {
        #[cfg(feature = "plugins")]
        if let Some(budget) = &self.budget {
            budget
                .take()
                .map_err(|_| oncl_pki::http::HttpError::other("plugin request budget exceeded"))?;
        }
        Ok(())
    }
}
impl oncl_pki::http::HttpTransport for ContextHttp<'_> {
    fn send(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        self.take()?;
        self.inner.send(request)
    }
    fn send_pinned(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
        pins: &[std::net::SocketAddr],
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        self.take()?;
        self.inner.send_pinned(request, pins)
    }
    fn send_scoped<'a>(
        &'a self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::ScopedHttpReply<'a>, oncl_pki::http::HttpError> {
        self.take()?;
        self.inner.send_scoped(request)
    }
    fn send_scoped_with<'a>(
        &'a self,
        request: &oncl_pki::http::HttpRequest<'_>,
        budget: oncl_pki::http::ResponseBudget<'a>,
    ) -> Result<oncl_pki::http::ScopedHttpReply<'a>, oncl_pki::http::HttpError> {
        self.take()?;
        self.inner.send_scoped_with(request, budget)
    }
    fn send_pinned_scoped<'a>(
        &'a self,
        request: &oncl_pki::http::HttpRequest<'_>,
        pins: &[std::net::SocketAddr],
        budget: oncl_pki::http::ResponseBudget<'a>,
    ) -> Result<oncl_pki::http::ScopedHttpReply<'a>, oncl_pki::http::HttpError> {
        self.take()?;
        self.inner.send_pinned_scoped(request, pins, budget)
    }
    fn resource_scope(&self) -> Option<&ResourceScope> {
        self.inner.resource_scope()
    }
    fn resource_failure(
        &self,
        error: oncl_pki::resource::ProcessingError,
    ) -> oncl_pki::http::HttpError {
        self.inner.resource_failure(error)
    }
}
