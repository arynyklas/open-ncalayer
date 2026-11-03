use super::*;
use oncl_core::OperationId;
use oncl_pki::resource::ResourceScope;

pub(super) struct OperationOutput {
    id: OperationId,
    scope: ResourceScope,
    context: Mutex<Option<OperationContext>>,
    _engine: Arc<Engine>,
    delivery: ResponseDelivery,
    failure: Arc<intake::Failure>,
    identity: Arc<()>,
    artifacts: Mutex<Vec<Arc<super::artifact::ArtifactState>>>,
    _metadata: ResourceReservation,
}
pub(super) struct ContextGuard {
    context: Option<OperationContext>,
    output: Arc<OperationOutput>,
}
pub(super) struct FrameBuffer {
    bytes: Vec<u8>,
    _reservation: ResourceReservation,
    _output: Arc<OperationOutput>,
}
impl AsRef<[u8]> for FrameBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl AsMut<[u8]> for FrameBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl FrameBuffer {
    pub(super) fn freeze(self) -> Bytes {
        Bytes::from_owner(self)
    }
}

struct JsonBuffer {
    bytes: Vec<u8>,
    metadata: ResourceReservation,
    failure: Arc<intake::Failure>,
}
impl std::io::Write for JsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = (|| -> Result<(), ProcessingError> {
            let required = self
                .bytes
                .len()
                .checked_add(bytes.len())
                .ok_or(ProcessingError::MetadataLimit)?;
            if required > self.bytes.capacity() {
                let old = self.bytes.capacity();
                let capacity = required.max(old.saturating_mul(2)).max(1024);
                self.metadata.grow(capacity as u64)?;
                let mut replacement = Vec::new();
                replacement
                    .try_reserve_exact(capacity)
                    .map_err(|_| ProcessingError::MemoryLimit)?;
                if replacement.capacity() != capacity {
                    return Err(ProcessingError::MemoryLimit);
                }
                replacement.extend_from_slice(&self.bytes);
                self.bytes = replacement;
                self.metadata.shrink(old as u64)?;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        })();
        result.map_err(|error| {
            self.failure.record(error);
            io::Error::other(self.failure.recover(ProcessingError::InvalidInput(
                "JSON output admission failed",
            )))
        })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl OperationOutput {
    pub(super) fn new(
        engine: Arc<Engine>,
        mut context: OperationContext,
        delivery: ResponseDelivery,
        failure: Arc<intake::Failure>,
        output_slots: usize,
    ) -> Result<(Arc<Self>, ContextGuard), ProcessingError> {
        let scope = context.resources().shared_view();
        if output_slots > 1024 {
            return Err(ProcessingError::MetadataLimit);
        }
        let slot_bytes = (output_slots as u64)
            .checked_mul(std::mem::size_of::<Arc<super::artifact::ArtifactState>>() as u64)
            .ok_or(ProcessingError::MetadataLimit)?;
        let metadata =
            scope.reserve_metadata(std::mem::size_of::<Self>() as u64 + 512 + slot_bytes)?;
        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(output_slots)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        if artifacts.capacity() != output_slots {
            return Err(ProcessingError::MemoryLimit);
        }
        let output = Arc::new(Self {
            id: context.id(),
            scope,
            context: Mutex::new(None),
            _engine: engine,
            delivery,
            failure,
            _metadata: metadata,
            identity: Arc::new(()),
            artifacts: Mutex::new(artifacts),
        });
        let guard = ContextGuard {
            context: Some(context),
            output: output.clone(),
        };
        Ok((output, guard))
    }
    pub(super) fn id(&self) -> OperationId {
        self.id
    }
    pub(super) fn scope(&self) -> &ResourceScope {
        &self.scope
    }
    pub(super) fn delivery(&self) -> &ResponseDelivery {
        &self.delivery
    }
    pub(super) fn failure(&self) -> &Arc<intake::Failure> {
        &self.failure
    }
    pub(super) fn identity(&self) -> &Arc<()> {
        &self.identity
    }
    pub(super) fn register_artifact(
        &self,
        artifact: Arc<super::artifact::ArtifactState>,
    ) -> Result<(), ProcessingError> {
        artifact.check_owner(self)?;
        let mut artifacts = self
            .artifacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if artifacts.len() == artifacts.capacity() {
            return Err(ProcessingError::MetadataLimit);
        }
        artifacts.push(artifact);
        Ok(())
    }
    pub(super) fn context_returned(&self) -> bool {
        self.context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
    pub(super) fn check_context(
        &self,
        context: &mut OperationContext,
    ) -> Result<(), ProcessingError> {
        if context.id() != self.id || !context.resources().same_operation(&self.scope) {
            return Err(ProcessingError::InvalidInput("foreign output context"));
        }
        Ok(())
    }
    fn buffer(
        self: &Arc<Self>,
        length: usize,
        reservation: ResourceReservation,
    ) -> Result<FrameBuffer, ProcessingError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        if bytes.capacity() != length {
            return Err(ProcessingError::MemoryLimit);
        }
        bytes.resize(length, 0);
        Ok(FrameBuffer {
            bytes,
            _reservation: reservation,
            _output: self.clone(),
        })
    }
    pub(super) fn data_buffer(
        self: &Arc<Self>,
        length: usize,
    ) -> Result<FrameBuffer, ProcessingError> {
        self.delivery.checkpoint()?;
        let reservation = self.scope.reserve_memory(length as u64)?;
        self.buffer(length, reservation)
    }
    pub(super) fn protocol_frame(self: &Arc<Self>, bytes: &[u8]) -> Result<Bytes, ProcessingError> {
        self.delivery.checkpoint()?;
        self.scope.account_output(bytes.len() as u64)?;
        let reservation = self.scope.reserve_metadata(bytes.len() as u64)?;
        let mut buffer = self.buffer(bytes.len(), reservation)?;
        buffer.as_mut().copy_from_slice(bytes);
        Ok(buffer.freeze())
    }
    pub(super) fn json_event<T: serde::Serialize>(
        self: &Arc<Self>,
        event: &T,
    ) -> Result<Bytes, ProcessingError> {
        self.delivery.checkpoint()?;
        let mut writer = JsonBuffer {
            bytes: Vec::new(),
            metadata: self.scope.reserve_metadata(0)?,
            failure: self.failure.clone(),
        };
        serde_json::to_writer(&mut writer, event).map_err(|_| {
            self.failure
                .recover(ProcessingError::InvalidInput("event serialization failed"))
        })?;
        self.scope.account_output(writer.bytes.len() as u64)?;
        Ok(Bytes::from_owner(FrameBuffer {
            bytes: writer.bytes,
            _reservation: writer.metadata,
            _output: self.clone(),
        }))
    }
}
impl ContextGuard {
    pub(super) fn context(&mut self) -> &mut OperationContext {
        self.context.as_mut().expect("live context guard")
    }
    pub(super) fn complete(mut self) -> Result<(), ProcessingError> {
        let output = self.output.clone();
        output.check_context(self.context())?;
        self.deposit();
        Ok(())
    }
    fn deposit(&mut self) {
        if let Some(context) = self.context.take() {
            let mut slot = self
                .output
                .context
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.is_none() {
                *slot = Some(context);
            } else {
                self.output
                    .failure
                    .record(ProcessingError::InvalidInput("duplicate output context"));
            }
        }
    }
}
impl Drop for ContextGuard {
    fn drop(&mut self) {
        self.deposit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{CancelOnDrop, Cancellation};
    use crate::service::ResponseDelivery;
    use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
    use oncl_pki::{
        io::Source,
        key::HashAlg,
        resource::{ProcessingError, ResourceLimits},
    };
    use std::sync::Arc;

    fn fixture() -> (Arc<Engine>, Arc<OperationOutput>, ContextGuard) {
        let engine = Arc::new(
            Engine::new(EngineServices::hash_only(ResourceLimits {
                max_in_flight: 1,
                ..ResourceLimits::default()
            }))
            .unwrap(),
        );
        let cancel = Arc::new(Cancellation::new());
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                cancel.clone(),
            )
            .unwrap();
        let delivery = ResponseDelivery {
            deadline: ctx.deadline(),
            cancel: cancel.clone(),
            control: ctx.resources().operation_control(),
            _disconnect: Arc::new(CancelOnDrop(cancel)),
        };
        let (root, guard) = OperationOutput::new(
            engine.clone(),
            ctx,
            delivery,
            Arc::new(super::super::intake::Failure::default()),
            1,
        )
        .unwrap();
        (engine, root, guard)
    }
    #[test]
    fn same_actual_context_moves_to_output_and_survives_the_last_network_slice() {
        let (engine, root, mut guard) = fixture();
        let id = guard.context().id();
        assert_eq!(root.id(), id);
        assert!(!root.context_returned());
        let report = engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut &b"abc"[..], None),
                guard.context(),
            )
            .unwrap();
        let bytes = root.protocol_frame(report.digest.as_bytes()).unwrap();
        guard.complete().unwrap();
        assert!(root.context_returned());
        let clone = bytes.clone();
        let slice = clone.slice(1..4);
        drop(bytes);
        drop(clone);
        drop(root);
        assert!(
            matches!(engine.admit(Arc::new(Cancellation::new())),Err(error)if error.code()==oncl_core::ErrorCode::CapacityExceeded)
        );
        drop(slice);
        assert!(engine.admit(Arc::new(Cancellation::new())).is_ok());
    }
    #[test]
    fn native_unwind_returns_owned_context_without_publishing_success() {
        let (engine, root, guard) = fixture();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = guard;
            panic!("owned context unwind");
        }));
        assert!(result.is_err());
        assert!(root.context_returned());
        assert!(engine.admit(Arc::new(Cancellation::new())).is_err());
        drop(root);
        assert!(engine.admit(Arc::new(Cancellation::new())).is_ok());
    }
    #[test]
    fn foreign_context_cannot_borrow_response_root_or_its_frame_quota() {
        let (_, root, mut original) = fixture();
        let foreign = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
        let mut ctx = foreign
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Cancellation::new()),
            )
            .unwrap();
        assert!(matches!(
            root.check_context(&mut ctx),
            Err(ProcessingError::InvalidInput(_))
        ));
        assert!(root.check_context(original.context()).is_ok());
    }
}
