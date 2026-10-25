//! `CommonInvoker` semantics: the "apiVersion 2" dispatcher behind `kz.gov.pki.knca.basics`.
//!
//! A request is a JSON object `{"apiVersion"?, "class"?, "method", "args"?}`; the reply is the
//! original's `CommonResponse`: `{"status":true,"body":…}` on success and
//! `{"status":false,"code",…}` on failure. `uuid` is never echoed.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::AddInfo;
use crate::envelope::to_json;

const GENERAL_ERROR: &str = "GENERAL_ERROR";
const GENERAL_MESSAGE: &str = "General error.";
const INVOCATION_ERROR: &str = "INVOCATION_ERROR";
const INVOCATION_MESSAGE: &str = "An invoked method threw an exception.";
const API_VERSION: i32 = 2;

/// Why a call failed; becomes the `code`/`message`/`details` of the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// `GENERAL_ERROR`, "General error.": the request could not be dispatched.
    General(Option<String>),
    /// `INVOCATION_ERROR`, "An invoked method threw an exception.": the method failed outside
    /// its own error model, e.g. on a missing argument.
    Invocation(Option<String>),
    /// A module-specific failure such as `SIGNING_FAILURE`; `message` is omitted when `None`.
    Custom {
        code: String,
        message: Option<String>,
        details: Option<String>,
    },
}

/// The outcome of a defined method: the reply `body` or a failure.
pub type CallResult = Result<Value, Failure>;

/// A class whose methods are reachable through `class` + `method` (`PKIExtras`,
/// `PKIEssentials` in the original).
pub trait NlClass: Send + Sync {
    /// The name matched against the request's `class`.
    fn class_name(&self) -> &'static str;
    /// Calls `method` with the request's `args` object (`None` when absent or not an object).
    /// Returns `None` if the class does not define `method`.
    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        add_info: &AddInfo,
    ) -> Option<CallResult>;
}

/// Dispatches a request to `classes` and returns the serialized reply. An empty or absent
/// `class` selects `classes[0]`.
pub fn invoke(request: &str, add_info: &AddInfo, classes: &[&dyn NlClass]) -> String {
    let reply = dispatch(request, add_info, classes);
    let response = match &reply {
        Ok(body) => CommonResponse {
            status: true,
            code: None,
            message: None,
            details: None,
            body: Some(body),
        },
        Err(failure) => {
            let (code, message, details) = match failure {
                Failure::General(details) => (GENERAL_ERROR, Some(GENERAL_MESSAGE), details),
                Failure::Invocation(details) => {
                    (INVOCATION_ERROR, Some(INVOCATION_MESSAGE), details)
                }
                Failure::Custom {
                    code,
                    message,
                    details,
                } => (code.as_str(), message.as_deref(), details),
            };
            CommonResponse {
                status: false,
                code: Some(code),
                message,
                details: details.as_deref(),
                body: None,
            }
        }
    };
    to_json(&response)
}

fn dispatch(request: &str, add_info: &AddInfo, classes: &[&dyn NlClass]) -> CallResult {
    let general = || Failure::General(None);
    let request: Value = serde_json::from_str(request).map_err(|_| general())?;
    let request = request.as_object().ok_or_else(general)?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(general)?;

    if opt_int(request.get("apiVersion"), API_VERSION) != API_VERSION {
        return Err(Failure::General(Some(format!(
            "Supported apiVersion is {API_VERSION}"
        ))));
    }

    let class = match request.get("class") {
        None | Some(Value::Null) => classes.first(),
        Some(Value::String(name)) if name.is_empty() => classes.first(),
        Some(Value::String(name)) => classes.iter().find(|c| c.class_name() == name),
        Some(_) => None,
    }
    .ok_or_else(general)?;

    let args = request.get("args").and_then(Value::as_object);
    class.call(method, args, add_info).unwrap_or_else(|| {
        Err(Failure::General(Some(format!(
            "{method} is not defined in {}",
            class.class_name()
        ))))
    })
}

/// org.json 20211205 `JSONObject.optInt(key, default)`, as `CommonInvoker` reads
/// `obj.optInt("apiVersion", 2)` (CommonInvoker.java:57).
///
/// `optInt` goes through `optNumber`: absent and `null` give `default`; a number is used as is;
/// anything else is `toString()`-ed and parsed by `stringToNumber`, falling back to `default` on
/// failure (so booleans, arrays, objects and non-numeric strings give `default`). The number is
/// then narrowed with `Number.intValue()`: fractions truncate toward zero and integers keep their
/// low 32 bits. Like org.json, strings are not trimmed (`" 2"` is non-numeric).
fn opt_int(value: Option<&Value>, default: i32) -> i32 {
    match value {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i as i32
            } else if let Some(u) = n.as_u64() {
                u as i32
            } else {
                n.as_f64().map_or(default, truncate)
            }
        }
        Some(Value::String(s)) => string_to_int(s).unwrap_or(default),
        _ => default,
    }
}

/// org.json `stringToNumber` followed by `intValue()`; `None` where it throws. Its `Double.valueOf`
/// retry for strings `BigDecimal` rejects (hex floats, `d`/`f` suffixes) is not emulated.
fn string_to_int(s: &str) -> Option<i32> {
    let initial = *s.as_bytes().first()?;
    if !(initial.is_ascii_digit() || initial == b'-') {
        return None;
    }
    if s.contains(['.', 'e', 'E']) || s == "-0" {
        // `new BigDecimal(s)`; without inf/nan its grammar is Rust's float grammar.
        let decimal = s
            .bytes()
            .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b));
        return decimal
            .then(|| s.parse::<f64>().ok())
            .flatten()
            .map(truncate);
    }
    // `new BigInteger(s)`; org.json first rejects octal-looking "01" and "-01".
    let digits = s.strip_prefix('-').unwrap_or(s);
    let octal = digits.len() > 1 && digits.starts_with('0');
    if octal || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let low = digits.bytes().fold(0u32, |acc, d| {
        acc.wrapping_mul(10).wrapping_add(u32::from(d - b'0'))
    });
    let low = if initial == b'-' {
        low.wrapping_neg()
    } else {
        low
    };
    Some(low as i32)
}

/// `BigDecimal.intValue()`/`Double.intValue()` for finite values: truncate toward zero, keep the
/// low 32 bits.
fn truncate(f: f64) -> i32 {
    f.trunc() as i128 as i32
}

/// The original's `CommonResponse`; fields serialize in declaration order and `None` fields are
/// omitted, as org.json does.
#[derive(Serialize)]
struct CommonResponse<'a> {
    status: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a Value>,
}
