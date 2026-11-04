//! Producer-selected output accounting; never an already-accounted public writer.
use crate::{Action, Engine, OperationContext, OperationError};
use oncl_pki::{
    io::{OutputTransaction, StagedArtifact},
    resource::{ProcessingError, ResourceScope},
};
use std::{
    io::{self, Write},
    sync::Arc,
};

pub(crate) enum ProducerOutput<'a> {
    Writer(&'a mut dyn Write),
    Staged(OutputTransaction<'a>),
}
impl<'a> ProducerOutput<'a> {
    pub(crate) fn staged(
        stage: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, OperationError> {
        Ok(Self::Staged(OutputTransaction::new(stage, scope)?))
    }
    pub(crate) fn write(
        &mut self,
        mut bytes: &[u8],
        scope: &ResourceScope,
    ) -> Result<(), OperationError> {
        match self {
            Self::Staged(transaction) => transaction.write_chunk(bytes)?,
            Self::Writer(writer) => {
                scope.account_output(bytes.len() as u64)?;
                while !bytes.is_empty() {
                    scope.checkpoint()?;
                    let count = match writer.write(bytes) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => result.map_err(ProcessingError::from)?,
                    };
                    if count == 0 || count > bytes.len() {
                        return Err(ProcessingError::Io(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "output made invalid progress",
                        ))
                        .into());
                    }
                    bytes = &bytes[count..];
                    scope.checkpoint()?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn finish(self, scope: &ResourceScope) -> Result<(), OperationError> {
        match self {
            Self::Staged(transaction) => transaction.finish()?,
            Self::Writer(writer) => {
                scope.checkpoint()?;
                writer.flush().map_err(ProcessingError::from)?;
                scope.checkpoint()?;
            }
        }
        Ok(())
    }
}
impl Engine {
    pub(crate) fn output_authority(
        &self,
        ctx: &OperationContext,
        action: Action,
    ) -> Result<(), OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if !ctx.grant.allows(action) {
            return Err(OperationError::PermissionDenied);
        }
        Ok(())
    }
}
