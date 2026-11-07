//! The closed telemetry vocabulary.
//!
//! Every attribute that can reach an OTLP payload is a [`SafeAttr`]. Its variants hold
//! only values of the small closed enums below; there is no constructor taking a
//! string, path, identifier or error text, so a forbidden value cannot be attached by
//! construction. Adding a dimension means adding an enum here and reviewing it.
use oncl_api::{
    dto::{Operation, SignKind},
    error::{ApiError, AppliedState, ErrorCode},
};
use opentelemetry::KeyValue;

/// Public route family. Health/OpenAPI are deliberately not observed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Route {
    Hash,
    Operations,
    Batch,
}
impl Route {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Operations => "operations",
            Self::Batch => "batch",
        }
    }
}

/// Operation family of one item (never an item id, document or key name).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OperationKind {
    Hash,
    Verify,
    Extract,
    Sign,
    Extend,
    JwsSign,
    JwsAdd,
    JwsVerify,
    JwtEncode,
    JwtDecode,
    JwtVerify,
    Plugin,
    Inspect,
    Stamp,
    VerifyStamp,
}
impl OperationKind {
    /// Exhaustive: a new operation must be classified here before it compiles.
    pub(crate) fn of(operation: &Operation) -> Self {
        match operation {
            Operation::Hash { .. } => Self::Hash,
            Operation::Verify { .. } => Self::Verify,
            Operation::Extract { .. } => Self::Extract,
            Operation::Sign { .. } => Self::Sign,
            Operation::Extend { .. } => Self::Extend,
            Operation::JwsSign { .. } => Self::JwsSign,
            Operation::JwsAdd { .. } => Self::JwsAdd,
            Operation::JwsVerify { .. } => Self::JwsVerify,
            Operation::JwtEncode { .. } => Self::JwtEncode,
            Operation::JwtDecode { .. } => Self::JwtDecode,
            Operation::JwtVerify { .. } => Self::JwtVerify,
            Operation::Plugin { .. } => Self::Plugin,
            Operation::Inspect { .. } => Self::Inspect,
            Operation::Stamp { .. } => Self::Stamp,
            Operation::VerifyStamp { .. } => Self::VerifyStamp,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Verify => "verify",
            Self::Extract => "extract",
            Self::Sign => "sign",
            Self::Extend => "extend",
            Self::JwsSign => "jws_sign",
            Self::JwsAdd => "jws_add",
            Self::JwsVerify => "jws_verify",
            Self::JwtEncode => "jwt_encode",
            Self::JwtDecode => "jwt_decode",
            Self::JwtVerify => "jwt_verify",
            Self::Plugin => "plugin",
            Self::Inspect => "inspect",
            Self::Stamp => "stamp",
            Self::VerifyStamp => "verify_stamp",
        }
    }
}

/// Signature format family (only for `sign`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Family {
    Cms,
    Cades,
    Pdf,
    Pades,
    Xml,
    Xades,
    Wsse,
    XmlLegacy,
    XadesLegacy,
}
impl Family {
    pub(crate) fn of(operation: &Operation) -> Option<Self> {
        let Operation::Sign { profile, .. } = operation else {
            return None;
        };
        Some(match profile {
            SignKind::Cms => Self::Cms,
            SignKind::CadesB | SignKind::CadesT | SignKind::CadesLt | SignKind::CadesLta => {
                Self::Cades
            }
            SignKind::Pdf => Self::Pdf,
            SignKind::PadesB | SignKind::PadesT | SignKind::PadesLt | SignKind::PadesLta => {
                Self::Pades
            }
            SignKind::Xml => Self::Xml,
            SignKind::XadesB | SignKind::XadesT => Self::Xades,
            SignKind::Wsse => Self::Wsse,
            SignKind::XmlLegacy => Self::XmlLegacy,
            SignKind::XadesLegacyB | SignKind::XadesLegacyT => Self::XadesLegacy,
        })
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Cms => "cms",
            Self::Cades => "cades",
            Self::Pdf => "pdf",
            Self::Pades => "pades",
            Self::Xml => "xml",
            Self::Xades => "xades",
            Self::Wsse => "wsse",
            Self::XmlLegacy => "xml_legacy",
            Self::XadesLegacy => "xades_legacy",
        }
    }
}

/// Result class. The detail is the separate stable [`ErrorClass`], never a message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Outcome {
    Ok,
    /// Refused before any work ran (permission, capacity, limits, audit availability).
    Rejected,
    Failed,
    /// Stopped by the client/cancellation.
    Aborted,
}
impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
        }
    }
}

/// The stable wire error code (closed enum of the public contract).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ErrorClass(ErrorCode);
impl ErrorClass {
    pub(crate) fn new(code: ErrorCode) -> Self {
        Self(code)
    }
    pub(crate) fn outcome(self, at_head: bool) -> Outcome {
        match self.0 {
            ErrorCode::Cancelled => Outcome::Aborted,
            _ if at_head => Outcome::Rejected,
            _ => Outcome::Failed,
        }
    }
    fn as_str(self) -> &'static str {
        match self.0 {
            ErrorCode::PermissionDenied => "permission_denied",
            ErrorCode::InteractionRequired => "interaction_required",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::CapacityExceeded => "capacity_exceeded",
            ErrorCode::DeadlineExceeded => "deadline_exceeded",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::InputLimit => "input_limit",
            ErrorCode::FramingLimit => "framing_limit",
            ErrorCode::MissingTemporaryStore => "missing_temporary_store",
            ErrorCode::MemoryLimit => "memory_limit",
            ErrorCode::TempLimit => "temp_limit",
            ErrorCode::MetadataLimit => "metadata_limit",
            ErrorCode::OutputLimit => "output_limit",
            ErrorCode::AuditUnavailable => "audit_unavailable",
            ErrorCode::MissingConfiguration => "missing_configuration",
            ErrorCode::KeyNotFound => "key_not_found",
            ErrorCode::ValidationFailed => "validation_failed",
            ErrorCode::OperationFailed => "operation_failed",
            ErrorCode::Internal => "internal",
        }
    }
}

/// Honest key-application state of an operation (a count dimension, no key identity).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Applied(pub(crate) AppliedState);
impl Applied {
    fn as_str(self) -> &'static str {
        match self.0 {
            AppliedState::NotApplied => "not_applied",
            AppliedState::Applied => "applied",
            AppliedState::Unknown => "unknown",
        }
    }
}

/// HTTP status of the response head: only a value of the public error contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Status(u16);
impl Status {
    pub(crate) const OK: Self = Self(200);
    pub(crate) fn of(error: &ApiError) -> Self {
        use axum::response::IntoResponse;
        Self(
            ApiError::new(error.code, error.applied)
                .into_response()
                .status()
                .as_u16(),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Delivery {
    Complete,
    /// The client left or the deadline/cancellation cut the body short.
    Aborted,
}
impl Delivery {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Aborted => "aborted",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Signal {
    Spans,
    Metrics,
}
impl Signal {
    fn as_str(self) -> &'static str {
        match self {
            Self::Spans => "spans",
            Self::Metrics => "metrics",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Stage {
    Wait,
    Run,
}
impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Wait => "wait",
            Self::Run => "run",
        }
    }
}

/// The only way to attach data to a span or a metric point.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SafeAttr {
    Route(Route),
    Kind(OperationKind),
    Family(Family),
    Outcome(Outcome),
    Error(ErrorClass),
    Applied(Applied),
    Status(Status),
    Delivery(Delivery),
    Signal(Signal),
    Stage(Stage),
}
impl SafeAttr {
    /// All permitted attribute keys, as exported. The receiver-side privacy test
    /// asserts the payload uses no other key.
    pub(crate) const KEYS: [&'static str; 10] = [
        "oncl.route",
        "oncl.operation.kind",
        "oncl.operation.family",
        "oncl.outcome",
        "oncl.error.code",
        "oncl.key.applied",
        "http.response.status_code",
        "oncl.delivery",
        "oncl.signal",
        "oncl.stage",
    ];
    pub(super) fn key_value(self) -> KeyValue {
        match self {
            Self::Route(v) => KeyValue::new(Self::KEYS[0], v.as_str()),
            Self::Kind(v) => KeyValue::new(Self::KEYS[1], v.as_str()),
            Self::Family(v) => KeyValue::new(Self::KEYS[2], v.as_str()),
            Self::Outcome(v) => KeyValue::new(Self::KEYS[3], v.as_str()),
            Self::Error(v) => KeyValue::new(Self::KEYS[4], v.as_str()),
            Self::Applied(v) => KeyValue::new(Self::KEYS[5], v.as_str()),
            Self::Status(v) => KeyValue::new(Self::KEYS[6], i64::from(v.0)),
            Self::Delivery(v) => KeyValue::new(Self::KEYS[7], v.as_str()),
            Self::Signal(v) => KeyValue::new(Self::KEYS[8], v.as_str()),
            Self::Stage(v) => KeyValue::new(Self::KEYS[9], v.as_str()),
        }
    }
}
