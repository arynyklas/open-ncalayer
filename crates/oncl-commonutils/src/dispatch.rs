//! The original's reflective dispatcher (`NCALayerCommonActivator.getModuleService`) over
//! the methods `CommonUtils.getDeclaredMethods()` returns, in declaration order:
//!
//! - `method` is read with org.json `getString`, `args` with `optJSONArray` (anything but an
//!   array is no arguments) and `uuid` with `optString`;
//! - the first method with that name and as many parameters as `args` has is taken, else
//!   `NoSuchMethodException <name>`;
//! - an array argument becomes a `String[]` for a `String[]` parameter (every element must
//!   be a string) and an `Object[]` otherwise; other values pass as org.json gives them;
//! - `Method.invoke` refuses private methods (`IllegalAccessException`) and arguments of
//!   another type than the parameter (`IllegalArgumentException`): a `String` parameter
//!   takes only a JSON string, a `boolean` only a JSON boolean, `null` nothing;
//! - a method's own reply gets the request's `uuid` when it is not empty; the dispatcher's
//!   errors never do.

use crate::CommonUtils;
use crate::methods::{self, Outcome};
use oncl_protocol::AddInfo;
use serde::Serialize;
use serde_json::{Map, Value};

/// The class whose members the dispatcher reaches, as Java names it in its messages.
const COMMON_UTILS_CLASS: &str = "kz.gov.pki.knca.CommonUtils";
/// The class the dispatcher runs in, the caller `Method.invoke` checks access for.
const ACTIVATOR_CLASS: &str = "kz.gov.pki.knca.NCALayerCommonActivator";

/// A Java parameter type of a public method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Param {
    /// `String`.
    Str,
    /// `String[]`.
    Strs,
    /// `boolean`.
    Bool,
}

/// A method body: what `Method.invoke` runs.
pub(crate) type Call = fn(&CommonUtils, &Args<'_>, &AddInfo) -> Outcome;

/// How `Method.invoke` treats a method.
enum Body {
    /// Public, with these parameter types.
    Public(&'static [Param], Call),
    /// Public, but every parameter is of a type no JSON value converts to
    /// (`java.util.function.Function`): every call is an argument type mismatch.
    Unconvertible,
    /// Private: every call is refused.
    Private,
}

/// A declared method of `CommonUtils`.
struct Method {
    name: &'static str,
    /// Number of parameters.
    arity: usize,
    body: Body,
}

use Param::{Bool, Str, Strs};

/// `CommonUtils.getDeclaredMethods()` in declaration order.
const METHODS: [Method; 18] = [
    Method {
        name: "setKeyInfoServices",
        arity: 1,
        body: Body::Unconvertible,
    },
    Method {
        name: "setKeyInfoSetterService",
        arity: 1,
        body: Body::Unconvertible,
    },
    Method {
        name: "getActiveTokens",
        arity: 0,
        body: Body::Public(&[], methods::get_active_tokens),
    },
    Method {
        name: "getKeyInfo",
        arity: 1,
        body: Body::Public(&[Str], methods::get_key_info),
    },
    Method {
        name: "signXml",
        arity: 5,
        body: Body::Public(&[Str, Str, Str, Str, Str], methods::sign_xml),
    },
    Method {
        name: "signXmls",
        arity: 5,
        body: Body::Public(&[Str, Str, Strs, Str, Str], methods::sign_xmls),
    },
    Method {
        name: "saveKey",
        arity: 2,
        body: Body::Private,
    },
    Method {
        name: "createCMSSignatureFromBase64",
        arity: 4,
        body: Body::Public(
            &[Str, Str, Str, Bool],
            methods::create_cms_signature_from_base64,
        ),
    },
    Method {
        name: "createCMSSignatureFromFile",
        arity: 4,
        body: Body::Public(
            &[Str, Str, Str, Bool],
            methods::create_cms_signature_from_file,
        ),
    },
    Method {
        name: "createCAdESFromBase64",
        arity: 4,
        body: Body::Public(&[Str, Str, Str, Bool], methods::create_cades_from_base64),
    },
    Method {
        name: "createCAdESFromFile",
        arity: 4,
        body: Body::Public(&[Str, Str, Str, Bool], methods::create_cades_from_file),
    },
    Method {
        name: "createCAdESFromBase64Hash",
        arity: 3,
        body: Body::Public(&[Str, Str, Str], methods::create_cades_from_base64_hash),
    },
    Method {
        name: "applyCAdEST",
        arity: 3,
        body: Body::Public(&[Str, Str, Str], methods::apply_cades_t),
    },
    Method {
        name: "showFileChooser",
        arity: 2,
        body: Body::Public(&[Str, Str], methods::show_file_chooser),
    },
    Method {
        name: "changeLocale",
        arity: 1,
        body: Body::Public(&[Str], methods::change_locale),
    },
    Method {
        name: "getBase64FromFile",
        arity: 1,
        body: Body::Private,
    },
    Method {
        name: "chooseFile",
        arity: 2,
        body: Body::Private,
    },
    Method {
        name: "getJson",
        arity: 1,
        body: Body::Private,
    },
];

/// An argument as `Method.invoke` receives it, after the array conversion.
enum Arg<'a> {
    /// A JSON value as org.json gives it.
    Value(&'a Value),
    /// A JSON array converted to `String[]`.
    Strs(Vec<&'a str>),
    /// A JSON array converted to `Object[]`.
    Objects,
}

/// The arguments of a public method, of its parameter types.
pub(crate) struct Args<'a>(Vec<Typed<'a>>);

/// An argument of the parameter's type.
enum Typed<'a> {
    Str(&'a str),
    Strs(Vec<&'a str>),
    Bool(bool),
}

impl<'a> Args<'a> {
    /// The `String` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `String` (a method table error).
    pub(crate) fn str(&self, i: usize) -> &'a str {
        match &self.0[i] {
            Typed::Str(s) => s,
            _ => panic!("parameter {i} is not a String"),
        }
    }

    /// The `String[]` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `String[]`.
    pub(crate) fn strs(&self, i: usize) -> &[&'a str] {
        match &self.0[i] {
            Typed::Strs(s) => s,
            _ => panic!("parameter {i} is not a String[]"),
        }
    }

    /// The `boolean` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `boolean`.
    pub(crate) fn bool(&self, i: usize) -> bool {
        match &self.0[i] {
            Typed::Bool(b) => *b,
            _ => panic!("parameter {i} is not a boolean"),
        }
    }
}

/// The reply: the original's `ResponseMessage` as org.json writes it (`null` fields left
/// out), with the request's `uuid` added to a method's own reply.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Reply<'a> {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_object: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uuid: Option<&'a str>,
}

/// Dispatches `request` and serializes the reply.
pub(crate) fn process(cu: &CommonUtils, request: &str, add_info: &AddInfo) -> String {
    match dispatch(cu, request, add_info) {
        Ok((outcome, uuid)) => {
            let uuid = (!uuid.is_empty()).then_some(uuid.as_str());
            match &outcome {
                Ok(object) => reply("200", None, object.as_ref(), uuid),
                Err(message) => reply("500", message.as_deref(), None, uuid),
            }
        }
        Err(message) => reply("500", Some(&message), None, None),
    }
}

fn reply(
    code: &'static str,
    message: Option<&str>,
    object: Option<&Value>,
    uuid: Option<&str>,
) -> String {
    serde_json::to_string(&Reply {
        code,
        message,
        response_object: object,
        uuid,
    })
    .expect("replies serialize")
}

/// The method's outcome with the request's `uuid` (`optString`), or the dispatcher's error
/// message.
fn dispatch(
    cu: &CommonUtils,
    request: &str,
    add_info: &AddInfo,
) -> Result<(Outcome, String), String> {
    let request: Value = serde_json::from_str(request).map_err(|e| e.to_string())?;
    let Value::Object(request) = request else {
        return Err("A JSONObject text must begin with '{' at 1 [character 2 line 1]".to_owned());
    };
    let uuid = opt_string(&request, "uuid");
    let name = match request.get("method") {
        None => return Err("JSONObject[\"method\"] not found.".to_owned()),
        Some(Value::String(name)) => name.as_str(),
        Some(_) => return Err("JSONObject[\"method\"] is not a string.".to_owned()),
    };
    let args: &[Value] = match request.get("args") {
        Some(Value::Array(args)) => args,
        _ => &[],
    };
    let Some(method) = METHODS
        .iter()
        .find(|m| m.name == name && m.arity == args.len())
    else {
        return Err(format!("NoSuchMethodException {name}"));
    };
    let args = convert(method, args)?;
    let (call, args) = match &method.body {
        Body::Private => {
            return Err(format!(
                "java.lang.IllegalAccessException: Class {ACTIVATOR_CLASS} can not access a \
                 member of class {COMMON_UTILS_CLASS} with modifiers \"private\". Method: {name}"
            ));
        }
        Body::Unconvertible => return Err(type_mismatch(name)),
        Body::Public(params, call) => {
            let typed = params
                .iter()
                .zip(args)
                .map(|(param, arg)| match (param, arg) {
                    (Param::Str, Arg::Value(Value::String(s))) => Some(Typed::Str(s)),
                    (Param::Bool, Arg::Value(Value::Bool(b))) => Some(Typed::Bool(*b)),
                    (Param::Strs, Arg::Strs(s)) => Some(Typed::Strs(s)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| type_mismatch(name))?;
            (call, Args(typed))
        }
    };
    let outcome = call(cu, &args, add_info);
    if let Err(message) = &outcome {
        tracing::debug!(
            method = name,
            message = message.as_deref(),
            "commonUtils call failed"
        );
    }
    Ok((outcome, uuid))
}

/// The dispatcher's array conversion: `String[]` for a `String[]` parameter, where every
/// element must be a string (org.json `getString`), `Object[]` otherwise.
fn convert<'a>(method: &Method, args: &'a [Value]) -> Result<Vec<Arg<'a>>, String> {
    args.iter()
        .enumerate()
        .map(|(i, arg)| match arg {
            Value::Array(items) => {
                let strs =
                    matches!(&method.body, Body::Public(params, _) if params[i] == Param::Strs);
                if !strs {
                    return Ok(Arg::Objects);
                }
                items
                    .iter()
                    .enumerate()
                    .map(|(j, item)| {
                        item.as_str()
                            .ok_or_else(|| format!("JSONArray[{j}] is not a String."))
                    })
                    .collect::<Result<_, _>>()
                    .map(Arg::Strs)
            }
            arg => Ok(Arg::Value(arg)),
        })
        .collect()
}

/// `Method.invoke`'s refusal of an argument of another type than its parameter.
fn type_mismatch(name: &str) -> String {
    format!("java.lang.IllegalArgumentException: argument type mismatch. Method: {name}")
}

/// org.json `optString`: absent and `null` are empty, a string is itself, anything else
/// its JSON text.
fn opt_string(obj: &Map<String, Value>, key: &str) -> String {
    match obj.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}
