use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    PermissionDenied,
    /// The operation would need an interactive confirmation; headless refuses.
    InteractionRequired,
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
/// Parsing is tolerant so older and newer peers interoperate: unknown fields are ignored and a
/// `subcode` that is not a well-formed string is dropped (the published OpenAPI schema stays
/// strict about what a server may send).
///
/// A typed error answer: the stable [`ErrorCode`], the honest key-application state and, for
/// a refusal that has one, a `subcode`: a short stable identifier of the precise reason
/// (for example a plugin key use the operator did not grant: `not-granted`).
///
/// The subcode is an additive field next to the code: the code set is unchanged, an error
/// without a subcode serializes exactly as before, and a subcode never replaces or widens
/// the code. It matches [`SUBCODE_PATTERN`]; anything else a peer sends is dropped on
/// parsing (the typed code survives), so a subcode is always safe to print.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub applied: AppliedState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient_subcode"
    )]
    subcode: Option<String>,
}
/// The published pattern of a subcode (also the OpenAPI `pattern`).
pub const SUBCODE_PATTERN: &str = "^[A-Za-z][A-Za-z0-9_-]{0,63}$";
/// Longest subcode.
pub const SUBCODE_MAX: usize = 64;
/// Whether `text` is a well-formed subcode ([`SUBCODE_PATTERN`]).
pub fn is_subcode(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= SUBCODE_MAX
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn lenient_subcode<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Loose {
        Text(String),
        Other(serde::de::IgnoredAny),
    }
    Ok(match Option::<Loose>::deserialize(deserializer)? {
        Some(Loose::Text(text)) if is_subcode(&text) => Some(text),
        _ => None,
    })
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppliedState {
    NotApplied,
    Applied,
    Unknown,
}
impl ApiError {
    pub fn not_applied(code: ErrorCode) -> Self {
        Self::new(code, AppliedState::NotApplied)
    }
    /// An error without a subcode.
    pub fn new(code: ErrorCode, applied: AppliedState) -> Self {
        Self {
            code,
            applied,
            subcode: None,
        }
    }
    /// The same error with `subcode`. Text that is not a well-formed subcode
    /// ([`is_subcode`]) is not carried: the error keeps its code only.
    #[must_use]
    pub fn with_subcode(mut self, subcode: impl Into<String>) -> Self {
        self.subcode = Some(subcode.into()).filter(|s| is_subcode(s));
        self
    }
    /// The precise reason, if the answer names one; always well-formed.
    pub fn subcode(&self) -> Option<&str> {
        self.subcode.as_deref()
    }
}
#[cfg(feature = "server")]
impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let status = match self.code {
            ErrorCode::PermissionDenied | ErrorCode::InteractionRequired => StatusCode::FORBIDDEN,
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
