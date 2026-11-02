use oncl_pki::key::{AppliedState, KeyError, KeyExecutionError, KeyFailureKind};
use oncl_pki::resource::ProcessingError;

/// Stable machine-readable execution categories; never inferred from messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    PermissionDenied,
    InvalidInput,
    Cancelled,
    DeadlineExceeded,
    CapacityExceeded,
    InputLimit,
    ContainerLimit,
    FramingLimit,
    OutputLimit,
    MemoryLimit,
    TempLimit,
    MetadataLimit,
    Io,
    MissingKeyProvider,
    SecretRequired,
    KeyNotFound,
    UnsupportedAlgorithm,
    AuditFailed,
    KeyFailure,
    MissingValidationServices,
    MissingCadesConfiguration,
    MissingTemporaryStore,
    ValidationRequired,
}

impl From<KeyFailureKind> for ErrorCode {
    fn from(kind: KeyFailureKind) -> Self {
        match kind {
            KeyFailureKind::PermissionDenied => Self::PermissionDenied,
            KeyFailureKind::InvalidContext
            | KeyFailureKind::IdExhausted
            | KeyFailureKind::InvalidKeySource
            | KeyFailureKind::InvalidLimits
            | KeyFailureKind::InvalidInput => Self::InvalidInput,
            KeyFailureKind::Cancelled => Self::Cancelled,
            KeyFailureKind::DeadlineExceeded => Self::DeadlineExceeded,
            KeyFailureKind::CapacityExceeded => Self::CapacityExceeded,
            KeyFailureKind::InputLimit => Self::InputLimit,
            KeyFailureKind::ContainerLimit => Self::ContainerLimit,
            KeyFailureKind::FramingLimit => Self::FramingLimit,
            KeyFailureKind::OutputLimit => Self::OutputLimit,
            KeyFailureKind::MemoryLimit => Self::MemoryLimit,
            KeyFailureKind::TempLimit => Self::TempLimit,
            KeyFailureKind::MetadataLimit => Self::MetadataLimit,
            KeyFailureKind::Io => Self::Io,
            KeyFailureKind::MissingKeyProvider => Self::MissingKeyProvider,
            KeyFailureKind::MissingValidationServices => Self::MissingValidationServices,
            KeyFailureKind::MissingCadesConfiguration => Self::MissingCadesConfiguration,
            KeyFailureKind::MissingTemporaryStore => Self::MissingTemporaryStore,
            KeyFailureKind::ValidationRequired => Self::ValidationRequired,
            KeyFailureKind::SecretRequired => Self::SecretRequired,
            KeyFailureKind::KeyNotFound => Self::KeyNotFound,
            KeyFailureKind::AuditFailed => Self::AuditFailed,
            KeyFailureKind::Backend => Self::KeyFailure,
        }
    }
}
impl From<&KeyError> for ErrorCode {
    fn from(error: &KeyError) -> Self {
        match error {
            KeyError::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            KeyError::Execution(error) => error.kind.into(),
            KeyError::WithAppliedState { source, .. } => Self::from(source.as_ref()),
            KeyError::Malformed(_)
            | KeyError::UnknownKeyAlgorithm(_)
            | KeyError::KeyMismatch
            | KeyError::BadSignature
            | KeyError::NotExportable
            | KeyError::Token(_)
            | KeyError::BackendFailure
            | KeyError::DecryptionFailed => Self::KeyFailure,
        }
    }
}

#[derive(Debug)]
pub enum OperationError {
    PermissionDenied,
    InvalidContext,
    IdExhausted,
    Processing(ProcessingError),
    MissingKeyProvider,
    MissingValidationServices,
    MissingCadesConfiguration,
    MissingTemporaryStore,
    ValidationRequired,
    SecretRequired,
    KeyNotFound,
    InvalidKeySource,
    AuditFailed,
    Key(oncl_pki::key::KeyError),
    AfterKeyUse {
        source: Box<OperationError>,
        applied: oncl_pki::key::AppliedState,
    },
}
impl OperationError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::PermissionDenied => ErrorCode::PermissionDenied,
            Self::InvalidContext | Self::IdExhausted => ErrorCode::InvalidInput,
            Self::MissingKeyProvider => ErrorCode::MissingKeyProvider,
            Self::MissingValidationServices => ErrorCode::MissingValidationServices,
            Self::MissingCadesConfiguration => ErrorCode::MissingCadesConfiguration,
            Self::MissingTemporaryStore => ErrorCode::MissingTemporaryStore,
            Self::ValidationRequired => ErrorCode::ValidationRequired,
            Self::SecretRequired => ErrorCode::SecretRequired,
            Self::KeyNotFound => ErrorCode::KeyNotFound,
            Self::InvalidKeySource => ErrorCode::InvalidInput,
            Self::AuditFailed => ErrorCode::AuditFailed,
            Self::AfterKeyUse { source, .. } => source.code(),
            Self::Key(error) => error.into(),
            Self::Processing(error) => KeyFailureKind::from(error).into(),
        }
    }
    pub fn applied_state(&self) -> AppliedState {
        match self {
            Self::AfterKeyUse { applied, .. } => *applied,
            Self::Key(error) => error.applied_state(),
            Self::PermissionDenied
            | Self::InvalidContext
            | Self::IdExhausted
            | Self::Processing(_)
            | Self::MissingKeyProvider
            | Self::MissingValidationServices
            | Self::MissingCadesConfiguration
            | Self::MissingTemporaryStore
            | Self::ValidationRequired
            | Self::SecretRequired
            | Self::KeyNotFound
            | Self::InvalidKeySource
            | Self::AuditFailed => AppliedState::NotApplied,
        }
    }
}
impl From<ProcessingError> for OperationError {
    fn from(error: ProcessingError) -> Self {
        Self::Processing(error)
    }
}
impl From<oncl_pki::key::KeyError> for OperationError {
    fn from(error: oncl_pki::key::KeyError) -> Self {
        Self::Key(error)
    }
}

/// One consuming conversion for every format adapter. Preserve raw key causes
/// and carry outer application knowledge separately, instead of round-tripping
/// through a reduced public-code enumeration.
impl From<OperationError> for KeyError {
    fn from(error: OperationError) -> Self {
        let kind = match error {
            OperationError::Key(error) => return error,
            OperationError::AfterKeyUse { source, applied } => {
                return Self::from(*source).with_applied_state(applied);
            }
            OperationError::Processing(error) => {
                return Self::Execution(KeyExecutionError::processing(
                    &error,
                    AppliedState::NotApplied,
                ));
            }
            OperationError::PermissionDenied => KeyFailureKind::PermissionDenied,
            OperationError::InvalidContext => KeyFailureKind::InvalidContext,
            OperationError::IdExhausted => KeyFailureKind::IdExhausted,
            OperationError::MissingKeyProvider => KeyFailureKind::MissingKeyProvider,
            OperationError::MissingValidationServices => KeyFailureKind::MissingValidationServices,
            OperationError::MissingCadesConfiguration => KeyFailureKind::MissingCadesConfiguration,
            OperationError::MissingTemporaryStore => KeyFailureKind::MissingTemporaryStore,
            OperationError::ValidationRequired => KeyFailureKind::ValidationRequired,
            OperationError::SecretRequired => KeyFailureKind::SecretRequired,
            OperationError::KeyNotFound => KeyFailureKind::KeyNotFound,
            OperationError::InvalidKeySource => KeyFailureKind::InvalidKeySource,
            OperationError::AuditFailed => KeyFailureKind::AuditFailed,
        };
        Self::Execution(KeyExecutionError {
            kind,
            applied: AppliedState::NotApplied,
        })
    }
}
impl std::fmt::Display for OperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied => f.write_str("action not granted"),
            Self::InvalidContext => f.write_str("operation context belongs to another engine"),
            Self::IdExhausted => f.write_str("operation identifier space exhausted"),
            Self::Processing(error) => std::fmt::Display::fmt(error, f),
            Self::MissingKeyProvider => f.write_str("key provider is not configured"),
            Self::MissingTemporaryStore => f.write_str("host temporary store is not configured"),
            Self::MissingValidationServices => {
                f.write_str("validation services are not configured")
            }
            Self::MissingCadesConfiguration => {
                f.write_str("CAdES acquisition configuration is not configured")
            }
            Self::ValidationRequired => {
                f.write_str("mandatory validation did not establish validity")
            }
            Self::SecretRequired => f.write_str("operation requires a secret"),
            Self::KeyNotFound => f.write_str("selected key was not found"),
            Self::InvalidKeySource => f.write_str("invalid key source or secret"),
            Self::AuditFailed => f.write_str("key-use audit failed"),
            Self::Key(error) => std::fmt::Display::fmt(error, f),
            Self::AfterKeyUse { source, applied } => {
                write!(f, "{source} (key application: {applied:?})")
            }
        }
    }
}
impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Processing(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::AfterKeyUse { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
