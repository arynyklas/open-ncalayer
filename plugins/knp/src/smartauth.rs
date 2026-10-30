//! The SmartAuth service of the cabinet: `POST https://<page host>/SmartAuthService/<call>`
//! without a `Content-Type`, the body an action message as protobuf-JSON (Gson with a proto
//! adapter: the proto's own field names, enums as numbers, set fields in field-number
//! order), the reply its result message the same way.
//!
//! The messages are those of `smartauth_types.proto` (package of the cabinet's backend);
//! only the fields the commands use are written and read.

use crate::Fail;
use oncl_pdk::http::{self, HttpExArgs, Method};
use oncl_pdk::serde_json::{Map, Value};

/// A protobuf-JSON value.
pub enum P {
    Str(String),
    Int(i64),
    Bool(bool),
    /// A message: its set fields in field-number order.
    Msg(Vec<(&'static str, P)>),
    Arr(Vec<P>),
}

impl P {
    pub fn str(s: impl Into<String>) -> P {
        P::Str(s.into())
    }

    fn write(&self, out: &mut String) {
        match self {
            P::Str(s) => gson_quote(s, out),
            P::Int(i) => out.push_str(&i.to_string()),
            P::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            P::Msg(fields) => {
                out.push('{');
                for (i, (name, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    gson_quote(name, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
            P::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
        }
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
}

/// A string as Gson's default writer escapes it (HTML-safe).
fn gson_quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '=' | '\'' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// An enum of the proto: its values by number.
pub type Enum = &'static [(i64, &'static str)];

pub const UIN_TYPE: Enum = &[(0, "IIN_BIN"), (1, "RNN")];
pub const CONFIRMATION_METHOD: Enum = &[(0, "MAIL"), (1, "SMS")];
pub const USER_AGREEMENT_TYPE: Enum = &[
    (0, "AGREEMENT_AUTH"),
    (1, "AGREEMENT_SIGN"),
    (100, "AGREEMENT_CANCEL_AUTH"),
    (101, "AGREEMENT_CANCEL_SIGN"),
];
pub const AGREEMENT_STATUS: Enum = &[
    (0, "AGREEMENT_SIGNED"),
    (1, "AGREEMENT_NOT_SIGNED"),
    (2, "AGREEMENT_CANCELLED"),
    (3, "AGREEMENT_SIGN_IN_FUTURE"),
    (4, "AGREEMENT_SIGN_EXPIRED"),
    (5, "AGREEMENT_SIGN_CERT_EXPIRED"),
    (6, "AGREEMENT_SIGN_CERT_REVOKED"),
];
/// The reply's names of `UserRegistrationStatus`, with the original's misspelling.
pub const USER_REGISTRATION_STATUS: Enum = &[(0, "USER_REGISTERED"), (1, "USER_NOT_REGISTRED")];
pub const UIN_VALIDATION_ERROR: Enum = &[
    (1, "UIN_INCORRECT_FORMAT"),
    (2, "UIN_INCORRECT"),
    (255, "UIN_VALIDATION_NOT_AVAILABLE_ERROR"),
];
pub const USER_STATUS_ERROR: Enum = &[
    (1, "USER_NOT_REGISTERED"),
    (2, "USER_ALREADY_REGISTERED"),
    (100, "AUTH_AGREEMENT_ERROR"),
    (101, "SIGN_AGREEMENT_ERROR"),
];
pub const SIGNED_XML_VALIDATION_ERROR: Enum = &[
    (1, "SIGN_NOT_FOUND"),
    (2, "SIGN_CERT_NOT_FOUND"),
    (3, "SIGN_CERT_REVOKED"),
    (4, "SIGN_CERT_EXPIRED"),
    (5, "SIGN_UNKNOWN_CA"),
    (6, "SIGN_INCONSISTENT"),
    (7, "SIGN_UNKNOWN_ERROR"),
    (100, "SIGNED_DATA_BROKEN"),
    (101, "SIGNED_WITHOUT_UIN"),
    (102, "SIGNED_WITH_OTHER_UIN"),
    (103, "SIGNED_DATA_OBSOLETE"),
];
pub const SENDING_CONFIRMATION_ERROR: Enum = &[
    (1, "NO_CONFIRMATION_METHOD_AVAILABLE"),
    (2, "ILLEGAL_CONFIRMATION_LANGUAGE"),
    (3, "SENDING_CONFIRMATION_LIMITS_EXCEEDED"),
    (100, "SENDING_CONFIRMATION_ILLEGAL_MAIL_FORMAT"),
    (101, "SENDING_CONFIRMATION_UNSUPPORTED_MAIL_DOMAIN"),
    (200, "SENDING_CONFIRMATION_ILLEGAL_PHONE_FORMAT"),
    (1_000_000, "SENDING_CONFIRMATION_COMMON_ERROR"),
];
pub const CHECK_CONFIRMATION_ERROR: Enum = &[
    (1, "CONFIRMATION_WRONG_OPERATION_ID"),
    (2, "CONFIRMATION_WRONG_CODE"),
    (3, "CONFIRMATION_EXPIRED"),
];
pub const AUTH_ERROR: Enum = &[(1, "WRONG_PASSWORD"), (2, "UNKNOWN_DEVICE")];
pub const NEW_PASSWORD_VALIDATION_ERROR: Enum = &[(1, "PASSWORD_TOO_SHORT")];
pub const AGREEMENT_STATUS_ERROR: Enum = &[
    (1, "AGREEMENT_ALREADY_SIGNED"),
    (2, "AGREEMENT_ALREADY_CANCELLED"),
    (3, "AGREEMENT_YET_NOT_SIGNED_ERROR"),
    (4, "AGREEMENT_SIGN_IN_FUTURE_ERROR"),
    (5, "AGREEMENT_SIGN_EXPIRED_ERROR"),
    (6, "AGREEMENT_SIGN_CERT_EXPIRED_ERROR"),
    (7, "AGREEMENT_SIGN_CERT_REVOKED_ERROR"),
    (8, "AGREEMENT_SIGNED_OTHER"),
];
pub const CREATE_AGREEMENT_XML_TO_SIGN_ERROR: Enum = &[
    (2, "AGREEMENT_XML_GENERATION_MUST_BE_WITH_PERIOD"),
    (3, "AGREEMENT_XML_GENERATION_MUST_BE_WITHOUT_PERIOD"),
    (4, "AGREEMENT_XML_GENERATION_INVALID_PERIOD"),
    (5, "AGREEMENT_XML_GENERATION_TOO_SHORT_PERIOD"),
    (6, "AGREEMENT_XML_GENERATION_FROM_IS_TOO_IN_PAST"),
];

/// The number of the value `name` of `values` (`valueOf`).
pub fn number(values: Enum, name: &str) -> Result<i64, Fail> {
    values
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(number, _)| *number)
        .ok_or(Fail::Generic)
}

/// The name of the value `number` of `values`.
pub fn name(values: Enum, number: i64) -> Result<&'static str, Fail> {
    values
        .iter()
        .find(|(n, _)| *n == number)
        .map(|(_, name)| *name)
        .ok_or(Fail::Generic)
}

/// An enum field of a result: its name, or (unset) the name of the enum's first value.
pub fn enum_field(
    result: &Map<String, Value>,
    field: &str,
    values: Enum,
) -> Result<&'static str, Fail> {
    match result.get(field) {
        None | Some(Value::Null) => Ok(values[0].1),
        Some(value) => name(values, value.as_i64().ok_or(Fail::Generic)?),
    }
}

/// A string field of a result, `""` if unset.
pub fn string_field(result: &Map<String, Value>, field: &str) -> String {
    result
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// What the service answered: the result of a `SUCCESS`, or of an `ERROR`.
pub enum Answer {
    Success(Map<String, Value>),
    Error(Map<String, Value>),
}

/// The status values of `ResultStatus` that are answers.
const SUCCESS: i64 = 0;
const ERROR: i64 = 10;

/// The service's base for the page's origin, as the original derives it: the host of the
/// origin with `https://` and no port.
fn base(origin: &str) -> Result<String, Fail> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or(Fail::Generic)?;
    let host: String = rest
        .chars()
        .take_while(|c| !matches!(c, ':' | '^' | '/'))
        .collect();
    Ok(format!("https://{host}/"))
}

/// Calls `call` with the action `action`. A network failure is tried again twice; any
/// other failure (not 200, not a result, a status other than `SUCCESS` and `ERROR`) is the
/// general error.
pub fn call(origin: &str, call: &str, action: &P) -> Result<Answer, Fail> {
    let args = HttpExArgs {
        method: Method::Post,
        url: format!("{}SmartAuthService/{call}", base(origin)?),
        relative_to_origin: false,
        headers: Vec::new(),
        content_type: None,
        body: action.to_json().into_bytes().into(),
        timeout_ms: None,
    };
    let mut attempts = 0;
    let response = loop {
        attempts += 1;
        match http::request_ex(&args) {
            Ok(response) => break response,
            Err(e) if e.code == oncl_pdk::abi::ErrorCode::Failed && attempts < 3 => continue,
            Err(_) => return Err(Fail::Generic),
        }
    };
    if response.status != 200 {
        return Err(Fail::Generic);
    }
    let result: Value =
        oncl_pdk::serde_json::from_slice(&response.body).map_err(|_| Fail::Generic)?;
    let Value::Object(result) = result else {
        return Err(Fail::Generic);
    };
    match result.get("status").and_then(Value::as_i64) {
        Some(SUCCESS) => Ok(Answer::Success(result)),
        Some(ERROR) => Ok(Answer::Error(result)),
        _ => Err(Fail::Generic),
    }
}

/// `UinInfo { type, uin }`.
pub fn uin_info(kind: i64, uin: &str) -> P {
    P::Msg(vec![("type", P::Int(kind)), ("uin", P::str(uin))])
}

/// `HardwareTokenBlock` with the stub values the original sends.
pub fn stub_token() -> P {
    // Unverified against the original: the stub values of the token block it sends with
    // `authInfo` (taken as those of `hardwarePair`).
    P::Msg(vec![
        ("id", P::str("hwtoken.id")),
        ("hash", P::str("hwtoken.hash")),
        ("parentId", P::str("hwtoken.parentId")),
        ("parentHash", P::str("hwtoken.parentHash")),
        ("hardwareId", P::str("hwtoken.hardwareId")),
    ])
}
