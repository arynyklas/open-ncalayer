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
const API_VERSION: i64 = 2;

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

    if let Some(version) = request.get("apiVersion")
        && version.as_i64() != Some(API_VERSION)
    {
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
