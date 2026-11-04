use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    PermissionDenied,
    InvalidRequest,
    CapacityExceeded,
    DeadlineExceeded,
    Cancelled,
    InputLimit,
    FramingLimit,
    MissingTemporaryStore,
    MemoryLimit,
    TempLimit,
    MetadataLimit,
    OutputLimit,
    AuditUnavailable,
    MissingConfiguration,
    KeyNotFound,
    ValidationFailed,
    OperationFailed,
    Internal,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub applied: AppliedState,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppliedState {
    NotApplied,
    Applied,
    Unknown,
}
impl ApiError {
    pub fn not_applied(code: ErrorCode) -> Self {
        Self {
            code,
            applied: AppliedState::NotApplied,
        }
    }
}
#[cfg(feature = "server")]
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let status = match self.code {
            ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::CapacityExceeded => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::Cancelled => StatusCode::REQUEST_TIMEOUT,
            ErrorCode::InputLimit
            | ErrorCode::FramingLimit
            | ErrorCode::MemoryLimit
            | ErrorCode::TempLimit
            | ErrorCode::MetadataLimit
            | ErrorCode::OutputLimit => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::AuditUnavailable
            | ErrorCode::MissingTemporaryStore
            | ErrorCode::MissingConfiguration => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::KeyNotFound => StatusCode::NOT_FOUND,
            ErrorCode::ValidationFailed | ErrorCode::OperationFailed => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, axum::Json(self)).into_response()
    }
}
