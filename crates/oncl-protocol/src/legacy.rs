//! The reflective dispatcher of the original's `commonUtils` and its clones
//! (`NCALayerCommonActivator.getModuleService`): a method of the target class found by name
//! and number of arguments, the arguments passed positionally, the method's own reply sent
//! as it is, with the request's `uuid` added through org.json.
//!
//! - The request is parsed by org.json; a failure is `{"code":"500","message":<its message>}`.
//! - `uuid` is read with `optString`, `method` with `getString` (a failure is a reply of its
//!   message), `args` with `optJSONArray` (anything but an array is no arguments).
//! - The first declared method with that name and as many parameters is taken, else
//!   [`LegacyClass::no_such_method`] (`NoSuchMethodException <name>`).
//! - An array argument becomes an `int[]` for a parameter an `int[]` fits (`Object`,
//!   `int[]`: every element must be an org.json int, else `JSONArray[j] is not a int.`),
//!   else a `String[]` for a `String[]` parameter (every element a string, else
//!   `JSONArray[j] is not a String.`), else an `Object[]`; other values pass as they are.
//! - [`LegacyClass::before_invoke`] runs, then `Method.invoke`: a private method is refused
//!   (`IllegalAccessException`), an argument of another type than its parameter too
//!   (`IllegalArgumentException: argument type mismatch`), an exception of the method is an
//!   `InvocationTargetException`; each with `. Method: <name>`.
//! - The method's reply: without a `uuid`, sent as it is (no reply at all is a dropped
//!   connection); with one, parsed again by org.json and given `"uuid"` (no reply: `500`
//!   without a message).
//!
//! Every reply of the dispatcher itself is the class's error bean (`code`, `message`), in
//! the key order of Java's `HashMap`, without the `uuid`.

use crate::orgjson::{self, JObject, JValue, int_value};
use crate::{AddInfo, Reply};
use serde_json::{Map, Value};

/// The parameter type of a public method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Param {
    /// `String`: only a JSON string.
    Str,
    /// `String[]`: only an array of strings.
    Strs,
    /// `boolean`: only a JSON boolean.
    Bool,
    /// `Object`: any value, `null` included; an array becomes an `int[]`.
    Object,
    /// `int[]`: only an array of ints.
    IntArray,
}

/// What a method returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A JSON text the method made of this object.
    Json(JObject),
    /// Any other text, JSON or not.
    Text(String),
    /// `null` (a `void` method too).
    Null,
    /// The method threw: `InvocationTargetException`.
    Thrown,
}

/// A method body: what `Method.invoke` runs.
pub type Call<C> = fn(&C, &Args<'_>, &AddInfo) -> Outcome;

/// What runs before `Method.invoke`, with the request.
pub type Hook<C> = fn(&C, &Map<String, Value>);

/// How `Method.invoke` treats a method.
pub enum LegacyBody<C: ?Sized + 'static> {
    /// Public, with these parameter types.
    Public(&'static [Param], Call<C>),
    /// Public, but every parameter is of a type no JSON value converts to (a
    /// `java.util.function.Function`, a `Collection`): every call is an argument type
    /// mismatch.
    Unconvertible,
    /// Private: every call is refused.
    Private,
    /// Private, taking one `Object`: an array argument is converted to `int[]` before the
    /// call is refused.
    PrivateTakingObject,
}

/// A declared method of the target class.
pub struct LegacyMethod<C: ?Sized + 'static> {
    /// Its name.
    pub name: &'static str,
    /// Its number of parameters.
    pub arity: usize,
    /// How it is called.
    pub body: LegacyBody<C>,
}

/// The bean of the dispatcher's own replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorBean {
    /// `ResponseMessage`: `responseObject`, `code`, `message`.
    ResponseMessage,
    /// `ResponseForJS`: `responseObjects`, `responseObject`, `code`, `message`.
    ResponseForJs,
}

/// The class a dispatcher reaches, `C` the module's state.
pub struct LegacyClass<C: ?Sized + 'static> {
    /// The class the dispatcher runs in, the caller `Method.invoke` checks access for:
    /// `kz.gov.pki.knca.NCALayerCommonActivator`.
    pub dispatcher: &'static str,
    /// The class whose methods are reached: `kz.gov.pki.knca.CommonUtils`.
    pub target: &'static str,
    /// `getDeclaredMethods()`, in that order.
    pub methods: &'static [LegacyMethod<C>],
    /// The bean of the dispatcher's own replies.
    pub error_bean: ErrorBean,
    /// The message of a method not found, given its name: usually
    /// [`no_such_method_exception`].
    pub no_such_method: fn(&C, &str) -> String,
    /// What runs right before `Method.invoke` (once the method is found and its arguments
    /// converted), with the request.
    pub before_invoke: Option<Hook<C>>,
}

/// `NoSuchMethodException <name>`.
pub fn no_such_method_exception<C: ?Sized>(_: &C, name: &str) -> String {
    format!("NoSuchMethodException {name}")
}

/// An argument as a public method receives it.
#[derive(Clone, Debug, PartialEq)]
pub enum Arg<'a> {
    /// A `String`.
    Str(&'a str),
    /// A `String[]`.
    Strs(Vec<&'a str>),
    /// A `boolean`.
    Bool(bool),
    /// An `Object` that is not an array, as org.json gives it (`null` included).
    Value(&'a Value),
    /// An `int[]` (an `int[]` parameter, or an array for an `Object` one).
    Ints(Vec<i32>),
}

/// The arguments of a public method, of its parameter types.
pub struct Args<'a>(Vec<Arg<'a>>);

impl<'a> Args<'a> {
    /// Argument `i`.
    pub fn get(&self, i: usize) -> &Arg<'a> {
        &self.0[i]
    }

    /// The `String` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `String` (a method table error).
    pub fn str(&self, i: usize) -> &'a str {
        match &self.0[i] {
            Arg::Str(s) => s,
            _ => panic!("parameter {i} is not a String"),
        }
    }

    /// The `String[]` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `String[]`.
    pub fn strs(&self, i: usize) -> &[&'a str] {
        match &self.0[i] {
            Arg::Strs(s) => s,
            _ => panic!("parameter {i} is not a String[]"),
        }
    }

    /// The `boolean` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `boolean`.
    pub fn bool(&self, i: usize) -> bool {
        match &self.0[i] {
            Arg::Bool(b) => *b,
            _ => panic!("parameter {i} is not a boolean"),
        }
    }
}

/// An argument after the dispatcher's array conversion.
enum Converted<'a> {
    Value(&'a Value),
    Strs(Vec<&'a str>),
    Ints(Vec<i32>),
    Objects,
}

/// Dispatches `request` to `class` with the state `ctx`.
pub fn dispatch<C: ?Sized>(
    ctx: &C,
    class: &LegacyClass<C>,
    request: &str,
    add_info: &AddInfo,
) -> Reply {
    let error = |message: Option<&str>| Reply::Text(error_reply(class.error_bean, message));
    // Only the keys the dispatcher reads are kept, unless the hook reads the request.
    let parsed = match class.before_invoke {
        Some(_) => orgjson::parse(request).map(|parsed| match parsed {
            JValue::Obj(parsed) => parsed,
            _ => unreachable!("parse gives an object"),
        }),
        None => orgjson::parse_only(request, &["uuid", "method", "args"]),
    };
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(message) => return error(Some(&message)),
    };
    let uuid = match parsed.get("uuid") {
        None | Some(JValue::Null) => String::new(),
        Some(value) => value.java_string(),
    };
    let name = match parsed.get("method") {
        Some(JValue::Str(name)) => name.clone(),
        None => return error(Some("JSONObject[\"method\"] not found.")),
        Some(_) => return error(Some("JSONObject[\"method\"] is not a string.")),
    };
    let request = parsed.into_map();
    let args: &[Value] = match request.get("args") {
        Some(Value::Array(args)) => args,
        _ => &[],
    };
    let Some(method) = class
        .methods
        .iter()
        .find(|m| m.name == name && m.arity == args.len())
    else {
        return error(Some(&(class.no_such_method)(ctx, &name)));
    };
    let converted = match convert(method, args) {
        Ok(converted) => converted,
        Err(message) => return error(Some(&message)),
    };
    if let Some(hook) = class.before_invoke {
        hook(ctx, &request);
    }
    let failed = |what: String| error(Some(&format!("{what}. Method: {name}")));
    let outcome = match &method.body {
        LegacyBody::Private | LegacyBody::PrivateTakingObject => {
            return failed(format!(
                "java.lang.IllegalAccessException: Class {} can not access a member of class \
                 {} with modifiers \"private\"",
                class.dispatcher, class.target
            ));
        }
        LegacyBody::Unconvertible => return failed(type_mismatch()),
        LegacyBody::Public(params, call) => {
            let typed = params
                .iter()
                .zip(converted)
                .map(|(param, arg)| match (param, arg) {
                    (Param::Str, Converted::Value(Value::String(s))) => Some(Arg::Str(s)),
                    (Param::Bool, Converted::Value(Value::Bool(b))) => Some(Arg::Bool(*b)),
                    (Param::Strs, Converted::Strs(s)) => Some(Arg::Strs(s)),
                    (Param::Object, Converted::Value(v)) => Some(Arg::Value(v)),
                    (Param::Object | Param::IntArray, Converted::Ints(i)) => Some(Arg::Ints(i)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>();
            let Some(typed) = typed else {
                return failed(type_mismatch());
            };
            call(ctx, &Args(typed), add_info)
        }
    };
    match outcome {
        Outcome::Thrown => failed("java.lang.reflect.InvocationTargetException".to_owned()),
        Outcome::Null if uuid.is_empty() => Reply::Drop,
        Outcome::Null => error(None),
        Outcome::Json(object) if uuid.is_empty() => Reply::Text(object.to_json()),
        Outcome::Text(text) if uuid.is_empty() => Reply::Text(text),
        Outcome::Json(object) => with_uuid(class.error_bean, &object.to_json(), &uuid),
        Outcome::Text(text) => with_uuid(class.error_bean, &text, &uuid),
    }
}

/// `new JSONObject(reply).put("uuid", uuid).toString()`, or the error of the parse.
fn with_uuid(bean: ErrorBean, reply: &str, uuid: &str) -> Reply {
    Reply::Text(match orgjson::parse(reply) {
        Ok(JValue::Obj(mut object)) => {
            object.put("uuid", uuid);
            object.to_json()
        }
        Ok(_) => unreachable!("parse gives an object"),
        Err(message) => error_reply(bean, Some(&message)),
    })
}

/// The error bean with code `500` and `message` (left out when `None`).
fn error_reply(bean: ErrorBean, message: Option<&str>) -> String {
    let mut object = JObject::hash_map();
    // The bean's properties as org.json finds them; only `code` and `message` are set.
    match bean {
        ErrorBean::ResponseMessage | ErrorBean::ResponseForJs => {
            object.put("code", "500");
            object.put_opt("message", message);
        }
    }
    object.to_json()
}

/// `Method.invoke`'s refusal of an argument of another type than its parameter.
fn type_mismatch() -> String {
    "java.lang.IllegalArgumentException: argument type mismatch".to_owned()
}

/// The dispatcher's array conversion.
fn convert<'a, C: ?Sized>(
    method: &LegacyMethod<C>,
    args: &'a [Value],
) -> Result<Vec<Converted<'a>>, String> {
    args.iter()
        .enumerate()
        .map(|(i, arg)| {
            let Value::Array(items) = arg else {
                return Ok(Converted::Value(arg));
            };
            let param = match &method.body {
                LegacyBody::Public(params, _) => Some(params[i]),
                LegacyBody::PrivateTakingObject => Some(Param::Object),
                LegacyBody::Private | LegacyBody::Unconvertible => None,
            };
            match param {
                Some(Param::Object | Param::IntArray) => items
                    .iter()
                    .enumerate()
                    .map(|(j, item)| {
                        int_value(item).ok_or_else(|| format!("JSONArray[{j}] is not a int."))
                    })
                    .collect::<Result<_, _>>()
                    .map(Converted::Ints),
                Some(Param::Strs) => items
                    .iter()
                    .enumerate()
                    .map(|(j, item)| {
                        item.as_str()
                            .ok_or_else(|| format!("JSONArray[{j}] is not a String."))
                    })
                    .collect::<Result<_, _>>()
                    .map(Converted::Strs),
                _ => Ok(Converted::Objects),
            }
        })
        .collect()
}
