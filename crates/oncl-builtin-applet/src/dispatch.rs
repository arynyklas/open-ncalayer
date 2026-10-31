//! The original's reflective dispatcher (`KNCAAppletActivator.registerModuleService`) over
//! the methods `Applet.getDeclaredMethods()` returns:
//!
//! - `class` and `uuid` are read with org.json `optString`, `method` with `getString`, `args`
//!   with `optJSONArray` (anything but an array is no arguments);
//! - `class` must be empty or `kz.gov.pki.knca.applet.Applet`; then the first method with
//!   that name and as many parameters as `args` has is taken, else
//!   `java.lang.NoSuchMethodException`;
//! - JSON `null` is Java `null`; an array argument becomes an `int[]` for an `int[]`
//!   parameter (every element must be an org.json int), a `String[]` for a `String[]`
//!   parameter (every element must be a string), else an `Object[]`; other values pass as
//!   org.json gives them;
//! - `Method.invoke` refuses private methods (`IllegalAccessException`) and arguments of
//!   another type than the parameter (`IllegalArgumentException`): a `String` parameter
//!   takes only a JSON string or `null`, an array parameter only an array or `null`;
//! - an exception the method throws is `java.lang.reflect.InvocationTargetException`;
//! - every failure is `{"errorCode":"<exception>. Method: <name>"}` without `uuid`; a
//!   method's `ResultWrapper` gets the request's `uuid` when it is not empty;
//! - the reply is a `JSONObject` (a `HashMap`): `result`, `errorCode`, `secondResult`,
//!   `uuid`, in this order of its buckets.
//!
//! `genExt`, `getProvider`, `setProvider` and `showTokenChooser` are left out: they are
//! `NoSuchMethodException` here.

use crate::{Core, keygen, methods};
use oncl_pdk::orgjson::{JObject, get_string, int_value, opt_string};
use serde_json::Value;

/// The class the dispatcher's instance is of, the only `class` besides an empty one.
const APPLET_CLASS: &str = "kz.gov.pki.knca.applet.Applet";
/// The class the dispatcher runs in, the caller `Method.invoke` checks access for.
const ACTIVATOR_CLASS: &str = "kz.gov.pki.knca.applet.osgi.KNCAAppletActivator";

/// The original's `ResultWrapper` as org.json's bean wrapping writes it (`null` fields left
/// out).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Wrapper {
    pub(crate) error_code: &'static str,
    pub(crate) result: Option<Value>,
    pub(crate) second_result: Option<Value>,
}

impl Wrapper {
    /// `new ResultWrapper()` without a result: `NONE`.
    pub(crate) fn none() -> Self {
        Wrapper {
            error_code: NONE,
            result: None,
            second_result: None,
        }
    }

    /// `NONE` with `result`.
    pub(crate) fn ok(result: impl Into<Value>) -> Self {
        Wrapper {
            result: Some(result.into()),
            ..Wrapper::none()
        }
    }

    /// `new ResultWrapper(code)`.
    pub(crate) fn error(code: &'static str) -> Self {
        Wrapper {
            error_code: code,
            ..Wrapper::none()
        }
    }
}

/// The `errorCode` of success.
const NONE: &str = "NONE";

/// An exception a method throws instead of returning, by its Java class (for the log only:
/// the reply is `InvocationTargetException`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Thrown(pub(crate) &'static str);

/// `java.lang.NullPointerException`: a `null` argument the method dereferences.
pub(crate) const NPE: Thrown = Thrown("java.lang.NullPointerException");

/// What `Method.invoke` gives back.
pub(crate) type Outcome = Result<Wrapper, Thrown>;

/// A method body.
type Call<C> = fn(&C, &Args<'_>) -> Outcome;

/// A Java parameter type of a public method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Param {
    /// `String`.
    Str,
    /// `String[]`.
    Strs,
    /// `int[]`.
    Ints,
}

use Param::{Ints, Str, Strs};

/// How `Method.invoke` treats a method.
enum Body<C> {
    /// Public, with these parameter types.
    Public(&'static [Param], Call<C>),
    /// Private, with this many parameters (none an array type): every call is refused.
    Private(usize),
}

/// A declared method of `Applet`.
struct Method<C> {
    name: &'static str,
    body: Body<C>,
}

impl<C> Method<C> {
    /// Number of parameters.
    fn arity(&self) -> usize {
        match &self.body {
            Body::Public(params, _) => params.len(),
            Body::Private(arity) => *arity,
        }
    }
}

/// `Applet.getDeclaredMethods()`, without `genExt`, `getProvider`, `setProvider` and
/// `showTokenChooser`. Names with their arity are unique, so the order does not matter.
fn methods<C: Core>() -> [Method<C>; 16] {
    [
        Method {
            name: "showFileChooser",
            body: Body::Public(&[Str, Str], methods::show_file_chooser::<C>),
        },
        Method {
            name: "browseKeyStore",
            body: Body::Public(&[Str, Str, Str], methods::browse_key_store::<C>),
        },
        Method {
            name: "setPassword",
            body: Body::Public(&[], methods::set_password::<C>),
        },
        Method {
            name: "setPassword",
            body: Body::Public(&[Str], methods::set_password_with_message::<C>),
        },
        Method {
            name: "loadSlotList",
            body: Body::Public(&[Str], methods::load_slot_list::<C>),
        },
        Method {
            name: "getPublicPartInfo",
            body: Body::Public(&[Str], methods::get_public_part_info::<C>),
        },
        Method {
            name: "genKeyPairAndGetPKCS10",
            body: Body::Public(
                &[Str, Str, Str, Strs, Strs, Ints, Str, Str, Str],
                keygen::gen_key_pair_and_get_pkcs10::<C>,
            ),
        },
        Method {
            name: "setX509CertToKeyStore",
            body: Body::Public(
                &[Str, Str, Str, Str],
                methods::set_x509_cert_to_key_store::<C>,
            ),
        },
        Method {
            name: "setX509CertToKeyStoreAndChangePassword",
            body: Body::Public(
                &[Str, Str, Str, Str, Str],
                methods::set_x509_cert_to_key_store_and_change_password::<C>,
            ),
        },
        Method {
            name: "changePassword",
            body: Body::Public(&[Str, Str, Str, Str], methods::change_password::<C>),
        },
        Method {
            name: "signXml",
            body: Body::Public(&[Str, Str, Str, Str], methods::sign_xml::<C>),
        },
        Method {
            name: "deleteEntry",
            body: Body::Public(&[Str, Str, Str], methods::delete_entry::<C>),
        },
        Method {
            name: "resetStorage",
            body: Body::Public(&[Str, Str], methods::reset_storage::<C>),
        },
        Method {
            name: "getTryCount",
            body: Body::Public(&[], methods::get_try_count::<C>),
        },
        Method {
            name: "setTryCount",
            body: Body::Private(1),
        },
        Method {
            name: "getStorage",
            body: Body::Private(1),
        },
    ]
}

/// An argument as `Method.invoke` receives it, after the array conversion.
enum Arg<'a> {
    /// A JSON value as org.json gives it.
    Value(&'a Value),
    /// A JSON array converted to `String[]`.
    Strs(Vec<&'a str>),
    /// A JSON array converted to `int[]`.
    Ints(Vec<i32>),
    /// A JSON array converted to `Object[]`.
    Objects,
}

/// An argument of the parameter's type; `None` is Java `null`.
enum Typed<'a> {
    Str(Option<&'a str>),
    Strs(Option<Vec<&'a str>>),
    Ints(Option<Vec<i32>>),
}

/// The arguments of a public method, of its parameter types.
pub(crate) struct Args<'a>(Vec<Typed<'a>>);

impl<'a> Args<'a> {
    /// The `String` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `String` (a method table error).
    pub(crate) fn str(&self, i: usize) -> Option<&'a str> {
        match &self.0[i] {
            Typed::Str(s) => *s,
            _ => panic!("parameter {i} is not a String"),
        }
    }

    /// The `String[]` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not a `String[]`.
    pub(crate) fn strs(&self, i: usize) -> Option<&[&'a str]> {
        match &self.0[i] {
            Typed::Strs(s) => s.as_deref(),
            _ => panic!("parameter {i} is not a String[]"),
        }
    }

    /// The `int[]` argument `i`.
    ///
    /// # Panics
    ///
    /// If parameter `i` is not an `int[]`.
    pub(crate) fn ints(&self, i: usize) -> Option<&[i32]> {
        match &self.0[i] {
            Typed::Ints(n) => n.as_deref(),
            _ => panic!("parameter {i} is not an int[]"),
        }
    }
}

/// Dispatches `request` and writes the reply as org.json does: the `ResultWrapper` bean
/// (its `null` fields left out) with the request's `uuid` put in, or the dispatcher's
/// `errorCode` alone.
pub(crate) fn process<C: Core>(core: &C, request: &str) -> String {
    let mut reply = JObject::hash_map();
    match dispatch(core, request) {
        Ok((wrapper, uuid)) => {
            reply
                .put("errorCode", wrapper.error_code)
                .put_opt("result", wrapper.result)
                .put_opt("secondResult", wrapper.second_result);
            if !uuid.is_empty() {
                reply.put("uuid", uuid);
            }
        }
        Err(message) => {
            reply.put("errorCode", message);
        }
    }
    reply.to_json()
}

/// The method's `ResultWrapper` with the request's `uuid` (`optString`), or the
/// dispatcher's `errorCode`.
fn dispatch<C: Core>(core: &C, request: &str) -> Result<(Wrapper, String), String> {
    // The method's name as far as it was read, for the failure text.
    let failure = |exception: &str, name: &str| format!("{exception}. Method: {name}");
    let request = match serde_json::from_str::<Value>(request) {
        Ok(Value::Object(request)) => request,
        // The server routes JSON objects only.
        _ => {
            return Err(failure(
                "org.json.JSONException: A JSONObject text must begin with '{' at 1 [character 2 line 1]",
                "",
            ));
        }
    };
    let class = opt_string(&request, "class").unwrap_or_default();
    let uuid = opt_string(&request, "uuid").unwrap_or_default();
    let name = get_string(&request, "method")
        .map_err(|e| failure(&format!("org.json.JSONException: {e}"), ""))?;
    let args: &[Value] = match request.get("args") {
        Some(Value::Array(args)) => args,
        _ => &[],
    };
    let methods = methods::<C>();
    let method = (!name.is_empty() && (class.is_empty() || class == APPLET_CLASS))
        .then(|| {
            methods
                .iter()
                .find(|m| m.name == name && m.arity() == args.len())
        })
        .flatten();
    let Some(method) = method else {
        return Err(failure("java.lang.NoSuchMethodException", name));
    };
    let args = convert(method, args).map_err(|e| failure(&e, name))?;
    let Body::Public(params, call) = &method.body else {
        return Err(failure(
            &format!(
                "java.lang.IllegalAccessException: Class {ACTIVATOR_CLASS} can not access a \
                 member of class {APPLET_CLASS} with modifiers \"private\""
            ),
            name,
        ));
    };
    let typed = params
        .iter()
        .zip(args)
        .map(|(param, arg)| match (param, arg) {
            (_, Arg::Value(Value::Null)) => Some(match param {
                Param::Str => Typed::Str(None),
                Param::Strs => Typed::Strs(None),
                Param::Ints => Typed::Ints(None),
            }),
            (Param::Str, Arg::Value(Value::String(s))) => Some(Typed::Str(Some(s))),
            (Param::Strs, Arg::Strs(s)) => Some(Typed::Strs(Some(s))),
            (Param::Ints, Arg::Ints(n)) => Some(Typed::Ints(Some(n))),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            failure(
                "java.lang.IllegalArgumentException: argument type mismatch",
                name,
            )
        })?;
    match call(core, &Args(typed)) {
        Ok(wrapper) => {
            if wrapper.error_code != NONE {
                core.debug(&format!(
                    "Applet call failed: method={name} code={}",
                    wrapper.error_code
                ));
            }
            Ok((wrapper, uuid))
        }
        Err(Thrown(exception)) => {
            core.debug(&format!(
                "Applet call threw: method={name} exception={exception}"
            ));
            Err(failure("java.lang.reflect.InvocationTargetException", name))
        }
    }
}

/// The dispatcher's array conversion: `int[]` for an `int[]` parameter (org.json `getInt`
/// of every element), `String[]` for a `String[]` parameter (`getString`), `Object[]`
/// otherwise.
fn convert<'a, C>(method: &Method<C>, args: &'a [Value]) -> Result<Vec<Arg<'a>>, String> {
    let param = |i: usize| match &method.body {
        Body::Public(params, _) => Some(params[i]),
        Body::Private(_) => None,
    };
    args.iter()
        .enumerate()
        .map(|(i, arg)| match (arg, param(i)) {
            (Value::Array(items), Some(Param::Ints)) => items
                .iter()
                .enumerate()
                .map(|(j, item)| {
                    int_value(item).ok_or_else(|| {
                        format!("org.json.JSONException: JSONArray[{j}] is not a int.")
                    })
                })
                .collect::<Result<_, _>>()
                .map(Arg::Ints),
            (Value::Array(items), Some(Param::Strs)) => items
                .iter()
                .enumerate()
                .map(|(j, item)| {
                    item.as_str().ok_or_else(|| {
                        format!("org.json.JSONException: JSONArray[{j}] is not a String.")
                    })
                })
                .collect::<Result<_, _>>()
                .map(Arg::Strs),
            (Value::Array(_), _) => Ok(Arg::Objects),
            (arg, _) => Ok(Arg::Value(arg)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::tests::NoCore;

    #[test]
    fn arities_are_unique() {
        let methods = methods::<NoCore>();
        for (i, a) in methods.iter().enumerate() {
            for b in &methods[i + 1..] {
                assert!(
                    a.name != b.name || a.arity() != b.arity(),
                    "{} declared twice with {} parameters",
                    a.name,
                    a.arity()
                );
            }
        }
    }
}
