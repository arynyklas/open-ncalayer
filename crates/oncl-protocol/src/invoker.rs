//! `CommonInvoker` semantics: the "apiVersion 2" dispatcher behind `kz.gov.pki.knca.basics`.
//!
//! A request is a JSON object `{"apiVersion"?, "class"?, "method", "args"?}`; the reply is the
//! original's `CommonResponse` as org.json writes it: `{"body":…,"status":true}` on success
//! and `{"code",…,"status":false}` on failure, the keys in the order of Java's `HashMap`
//! (`body,status`; `code,details,message,status`), strings escaped as org.json escapes them.
//! A failure of the dispatcher itself has its `IllegalArgumentException` as `details`
//! (`Throwable.toString()`). `uuid` is never echoed.
//!
//! [`invoke`] reads the request with `serde_json` and writes the objects of `body` in the
//! order the method put their keys. [`java`] is the original's dispatcher to the byte, which
//! the basics module answers with: org.json parsing, the key order of Java's `HashMap` inside
//! `body` too, and what happens to a request that fails before the dispatcher's `try`.

pub mod java;

use serde_json::{Map, Value};

use crate::AddInfo;
use crate::javaexc::Throwable;
use crate::orgjson::{JObject, JValue, opt_int};

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
    match dispatch(request, add_info, classes) {
        Ok(body) => {
            let mut reply = JObject::hash_map();
            reply.put("status", true);
            reply.put("body", in_order(body));
            reply.to_json()
        }
        Err(failure) => java::failure_json(&failure),
    }
}

fn dispatch(request: &str, add_info: &AddInfo, classes: &[&dyn NlClass]) -> CallResult {
    let general = || Failure::General(None);
    let iae = |message: String| Failure::General(Some(Throwable::iae(message).to_string()));
    let request: Value = serde_json::from_str(request).map_err(|_| general())?;
    let request = request.as_object().ok_or_else(general)?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(general)?;

    if opt_int(request, "apiVersion", API_VERSION) != API_VERSION {
        return Err(iae(format!("Supported apiVersion is {API_VERSION}")));
    }

    // `optString("class")`: a value that is not a string is its text.
    let name = match request.get("class") {
        None | Some(Value::Null) => String::new(),
        Some(value) => JValue::from(value.clone()).java_string(),
    };
    let class = if name.is_empty() {
        classes.first()
    } else {
        classes.iter().find(|c| c.class_name() == name)
    }
    .ok_or_else(|| iae(format!("{name} is not found")))?;

    let args = request.get("args").and_then(Value::as_object);
    class.call(method, args, add_info).unwrap_or_else(|| {
        Err(iae(format!(
            "{method} is not defined in {}",
            class.class_name()
        )))
    })
}

/// `body` as org.json writes it, the keys of its objects in the order the method put them.
fn in_order(body: Value) -> JValue {
    match body {
        Value::Object(map) => {
            let mut object = JObject::stringer();
            for (key, value) in map {
                object.put(key, in_order(value));
            }
            JValue::Obj(object)
        }
        Value::Array(items) => JValue::Arr(items.into_iter().map(in_order).collect()),
        other => JValue::from(other),
    }
}
