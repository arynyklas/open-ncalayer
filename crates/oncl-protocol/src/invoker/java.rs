//! The original's `CommonInvoker` to the byte, for plugins answering in its dialect.
//!
//! Before its `try`, the dispatcher parses the request with org.json, reads `apiVersion`
//! (`optInt`, default 2), `class` (`optString`: a non-string is its text), `method`
//! (`getString`) and `args` (`optJSONObject`); an exception there leaves the dispatcher, and
//! what the page sees is the plugin's choice ([`BadRequest`]). Inside the `try`, in this
//! order, each a `GENERAL_ERROR` whose `details` is the `IllegalArgumentException`:
//! `Supported apiVersion is 2`, `<class> is not found`, `<method> is not defined in
//! <Class>`, `<method> demands arguments` (a method with parameters called without an
//! `args` object). A method without parameters gets no `args`.
//!
//! The reply is `CommonResponse` wrapped by org.json: `{"body":…,"status":true}` (no `body`
//! for a `null` result) or `{"code":…,"details":…,"message":…,"status":false}`, the key
//! order of Java's `HashMap`, strings escaped as org.json escapes them.

use super::Failure;
use crate::orgjson::{self, JObject, JValue};
use crate::{AddInfo, Reply};
use serde_json::{Map, Value};

const GENERAL_ERROR: &str = "GENERAL_ERROR";
const GENERAL_MESSAGE: &str = "General error.";
const INVOCATION_ERROR: &str = "INVOCATION_ERROR";
const INVOCATION_MESSAGE: &str = "An invoked method threw an exception.";
const API_VERSION: i32 = 2;
const IAE: &str = "java.lang.IllegalArgumentException: ";

/// The outcome of a method: the reply's `body` (`JValue::Null`: no `body`) or a failure.
/// A `String` body is a JSON string: a method that returns JSON text has it encoded twice,
/// as the original does.
pub type CallResult = Result<JValue, Failure>;

/// A public method annotated `@NCALayerMethod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NlMethod {
    /// Its Java name.
    pub name: &'static str,
    /// The annotation's `name`, if it has one.
    pub annotation: Option<&'static str>,
    /// Its number of parameters: 0 (`m()`), 1 (`m(args)`), 2 (`m(args, addInfo)`).
    pub params: u8,
}

/// A class of the dispatcher.
pub trait NlClass: Send + Sync {
    /// Its simple name, matched against the request's `class`.
    fn class_name(&self) -> &'static str;
    /// Its annotated methods (inherited ones included), in `getMethods()` order.
    fn methods(&self) -> &'static [NlMethod];
    /// Calls `method` (one of [`NlClass::methods`]) with the request's `args` object
    /// (`None` for a method without parameters).
    fn call(
        &self,
        method: &NlMethod,
        args: Option<&Map<String, Value>>,
        add_info: &AddInfo,
    ) -> CallResult;
}

/// What a request that fails before the dispatcher's `try` gets: one that org.json cannot
/// parse, or whose `method` is missing or not a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadRequest {
    /// `GENERAL_ERROR` without `details`, as the built-in modules answer.
    Reply,
    /// No reply: the exception left the module, the connection is dropped.
    Drop,
    /// `GENERAL_ERROR` with `details` the `org.json.JSONException`: the module caught it.
    CatchAll,
}

/// How the dispatcher behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvokeOptions {
    /// See [`BadRequest`].
    pub bad_request: BadRequest,
}

/// Dispatches `request` to `classes` (an empty or absent `class` selects the first).
pub fn invoke_with(
    request: &str,
    add_info: &AddInfo,
    classes: &[&dyn NlClass],
    options: &InvokeOptions,
) -> Reply {
    let parsed = match read(request) {
        Ok(parsed) => parsed,
        Err(exception) => {
            return match options.bad_request {
                BadRequest::Drop => Reply::Drop,
                BadRequest::Reply => failure(&Failure::General(None)),
                BadRequest::CatchAll => failure(&Failure::General(Some(format!(
                    "org.json.JSONException: {exception}"
                )))),
            };
        }
    };
    match dispatch(&parsed, add_info, classes) {
        Ok(JValue::Null) => {
            let mut reply = JObject::hash_map();
            reply.put("status", true);
            Reply::Text(reply.to_json())
        }
        Ok(body) => {
            let mut reply = JObject::hash_map();
            reply.put("status", true);
            reply.put("body", body);
            Reply::Text(reply.to_json())
        }
        Err(e) => failure(&e),
    }
}

/// What the dispatcher reads before its `try`.
struct Parsed {
    api_version: i32,
    class: String,
    method: String,
    args: Option<Map<String, Value>>,
}

/// Reads the request as the dispatcher does before its `try`; an error is the
/// `JSONException` message.
fn read(request: &str) -> Result<Parsed, String> {
    let JValue::Obj(object) = orgjson::parse(request)? else {
        unreachable!("parse gives an object");
    };
    let map = object.to_map();
    let class = match object.get("class") {
        None | Some(JValue::Null) => String::new(),
        Some(value) => value.java_string(),
    };
    let method = match object.get("method") {
        Some(JValue::Str(method)) => method.clone(),
        None => return Err("JSONObject[\"method\"] not found.".to_owned()),
        Some(_) => return Err("JSONObject[\"method\"] is not a string.".to_owned()),
    };
    Ok(Parsed {
        api_version: orgjson::opt_int(&map, "apiVersion", API_VERSION),
        class,
        method,
        args: orgjson::opt_object(&map, "args").cloned(),
    })
}

fn dispatch(parsed: &Parsed, add_info: &AddInfo, classes: &[&dyn NlClass]) -> CallResult {
    let iae = |message: String| Err(Failure::General(Some(format!("{IAE}{message}"))));
    if parsed.api_version != API_VERSION {
        return iae(format!("Supported apiVersion is {API_VERSION}"));
    }
    let class = if parsed.class.is_empty() {
        classes.first()
    } else {
        classes.iter().find(|c| c.class_name() == parsed.class)
    };
    let Some(class) = class else {
        return iae(format!("{} is not found", parsed.class));
    };
    let name = parsed.method.as_str();
    // `""` would match every annotation without a name, in an order the JVM does not fix:
    // it matches none here.
    let found = class
        .methods()
        .iter()
        .find(|m| !name.is_empty() && (m.name == name || m.annotation == Some(name)));
    let Some(method) = found else {
        return iae(format!("{name} is not defined in {}", class.class_name()));
    };
    if method.params == 0 {
        return class.call(method, None, add_info);
    }
    let Some(args) = &parsed.args else {
        return iae(format!("{name} demands arguments"));
    };
    class.call(method, Some(args), add_info)
}

/// The failure reply of `failure`.
fn failure(failure: &Failure) -> Reply {
    let (code, message, details) = match failure {
        Failure::General(details) => (GENERAL_ERROR, Some(GENERAL_MESSAGE), details),
        Failure::Invocation(details) => (INVOCATION_ERROR, Some(INVOCATION_MESSAGE), details),
        Failure::Custom {
            code,
            message,
            details,
        } => (code.as_str(), message.as_deref(), details),
    };
    let mut reply = JObject::hash_map();
    reply.put("status", false);
    reply.put("code", code);
    reply.put_opt("message", message);
    reply.put_opt("details", details.as_deref());
    Reply::Text(reply.to_json())
}
