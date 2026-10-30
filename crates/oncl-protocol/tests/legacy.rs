//! The reflective dispatcher of `commonUtils` and its clones, on a class of its own.

use oncl_protocol::legacy::{
    Arg, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param, dispatch,
    no_such_method_exception,
};
use oncl_protocol::orgjson::{JObject, JValue, opt_string};
use oncl_protocol::{AddInfo, Reply};
use serde_json::{Map, Value, json};
use std::sync::Mutex;

/// The module's state: the language of the NLDoc-like class, the calls made.
#[derive(Default)]
struct Ctx {
    lang: Mutex<String>,
    calls: Mutex<Vec<String>>,
}

impl Ctx {
    fn called(&self, what: impl Into<String>) {
        self.calls.lock().unwrap().push(what.into());
    }
}

/// `ResponseMessage` with `responseObject` and code 200.
fn ok(object: impl Into<JValue>) -> Outcome {
    let mut bean = JObject::hash_map();
    bean.put("code", "200").put("responseObject", object);
    Outcome::Json(bean)
}

fn get_active_tokens(ctx: &Ctx, _: &Args<'_>, _: &AddInfo) -> Outcome {
    ctx.called("getActiveTokens");
    ok(JValue::Arr(vec![]))
}

fn get_key_info(ctx: &Ctx, args: &Args<'_>, _: &AddInfo) -> Outcome {
    ctx.called(format!("getKeyInfo {}", args.str(0)));
    let mut bean = JObject::hash_map();
    bean.put("code", "500").put("message", "storage.unknown");
    Outcome::Json(bean)
}

fn sign_xmls(ctx: &Ctx, args: &Args<'_>, _: &AddInfo) -> Outcome {
    ctx.called(format!("signXmls {:?}", args.strs(2)));
    ok(JValue::Arr(
        args.strs(2).iter().map(|s| JValue::from(*s)).collect(),
    ))
}

fn create_cades(ctx: &Ctx, args: &Args<'_>, _: &AddInfo) -> Outcome {
    ctx.called(format!("createCAdES {}", args.bool(3)));
    ok("cms")
}

fn change_lang(ctx: &Ctx, args: &Args<'_>, _: &AddInfo) -> Outcome {
    *ctx.lang.lock().unwrap() = args.str(0).to_owned();
    Outcome::Null
}

fn plain(_: &Ctx, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Text("true plain".to_owned())
}

fn text_json(_: &Ctx, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Text(r#"{"errorCode":"NONE","errorMessage":"</x>"}"#.to_owned())
}

fn throws(_: &Ctx, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Outcome::Thrown
}

fn object(ctx: &Ctx, args: &Args<'_>, _: &AddInfo) -> Outcome {
    ctx.called(format!("object {:?}", args.get(0)));
    ok(true)
}

fn ints(ctx: &Ctx, args: &Args<'_>, _: &AddInfo) -> Outcome {
    ctx.called(format!("ints {:?}", args.get(0)));
    ok(true)
}

use Param::{Bool, Str, Strs};

const METHODS: &[LegacyMethod<Ctx>] = &[
    LegacyMethod {
        name: "setKeyInfoServices",
        arity: 1,
        body: LegacyBody::Unconvertible,
    },
    LegacyMethod {
        name: "getActiveTokens",
        arity: 0,
        body: LegacyBody::Public(&[], get_active_tokens),
    },
    LegacyMethod {
        name: "getKeyInfo",
        arity: 1,
        body: LegacyBody::Public(&[Str], get_key_info),
    },
    LegacyMethod {
        name: "signXmls",
        arity: 5,
        body: LegacyBody::Public(&[Str, Str, Strs, Str, Str], sign_xmls),
    },
    LegacyMethod {
        name: "saveKey",
        arity: 2,
        body: LegacyBody::Private,
    },
    LegacyMethod {
        name: "createCAdESFromBase64",
        arity: 4,
        body: LegacyBody::Public(&[Str, Str, Str, Bool], create_cades),
    },
    LegacyMethod {
        name: "getJson",
        arity: 1,
        body: LegacyBody::PrivateTakingObject,
    },
    LegacyMethod {
        name: "changeLang",
        arity: 1,
        body: LegacyBody::Public(&[Str], change_lang),
    },
    LegacyMethod {
        name: "plain",
        arity: 0,
        body: LegacyBody::Public(&[], plain),
    },
    LegacyMethod {
        name: "textJson",
        arity: 0,
        body: LegacyBody::Public(&[], text_json),
    },
    LegacyMethod {
        name: "throws",
        arity: 0,
        body: LegacyBody::Public(&[], throws),
    },
    LegacyMethod {
        name: "object",
        arity: 1,
        body: LegacyBody::Public(&[Param::Object], object),
    },
    LegacyMethod {
        name: "ints",
        arity: 1,
        body: LegacyBody::Public(&[Param::IntArray], ints),
    },
];

const CLASS: LegacyClass<Ctx> = LegacyClass {
    dispatcher: "kz.gov.pki.knca.NCALayerCommonActivator",
    target: "kz.gov.pki.knca.CommonUtils",
    methods: METHODS,
    error_bean: ErrorBean::ResponseMessage,
    no_such_method: no_such_method_exception,
    before_invoke: None,
};

/// NLDoc's message of a method not found, in the module's language now.
fn localized_no_such_method(ctx: &Ctx, name: &str) -> String {
    match ctx.lang.lock().unwrap().as_str() {
        "kk" => format!("Модульде мұндай әдіс жоқ {name}"),
        _ => format!("В модуле нет такого метода {name}"),
    }
}

/// NLDoc: the request's `lang` goes into effect right before the method runs.
fn lang_hook(ctx: &Ctx, request: &Map<String, Value>) {
    let lang = opt_string(request, "lang").unwrap_or_default();
    *ctx.lang.lock().unwrap() = if lang == "kk" { "kk" } else { "ru" }.to_owned();
}

const NLDOC: LegacyClass<Ctx> = LegacyClass {
    dispatcher: "kz.gov.pki.cms.NLDocSignerActivator",
    target: "kz.gov.pki.cms.CMSSignUtil",
    methods: METHODS,
    error_bean: ErrorBean::ResponseForJs,
    no_such_method: localized_no_such_method,
    before_invoke: Some(lang_hook),
};

fn raw(ctx: &Ctx, class: &LegacyClass<Ctx>, request: &str) -> Reply {
    dispatch(ctx, class, request, &AddInfo::default())
}

fn call(ctx: &Ctx, request: Value) -> String {
    raw(ctx, &CLASS, &request.to_string()).into_text().unwrap()
}

fn method(ctx: &Ctx, name: &str, args: Value) -> String {
    call(ctx, json!({"method": name, "args": args}))
}

fn error(message: &str) -> String {
    let mut bean = JObject::hash_map();
    bean.put("code", "500").put("message", message);
    bean.to_json()
}

#[test]
fn replies_are_sent_as_the_method_made_them() {
    let ctx = Ctx::default();
    assert_eq!(
        method(&ctx, "getActiveTokens", json!([])),
        r#"{"responseObject":[],"code":"200"}"#
    );
    // Anything but an array is no arguments (`optJSONArray`).
    assert_eq!(
        call(&ctx, json!({"method": "getActiveTokens", "args": "x"})),
        r#"{"responseObject":[],"code":"200"}"#
    );
    assert_eq!(method(&ctx, "plain", json!([])), "true plain");
    assert_eq!(
        method(&ctx, "textJson", json!([])),
        r#"{"errorCode":"NONE","errorMessage":"</x>"}"#
    );
}

#[test]
fn uuid_is_echoed_on_method_replies_only() {
    let ctx = Ctx::default();
    let req = |name: &str, args: Value, uuid: Value| {
        call(&ctx, json!({"method": name, "args": args, "uuid": uuid}))
    };
    assert_eq!(
        req("getKeyInfo", json!(["NOPE"]), json!("abc")),
        r#"{"code":"500","message":"storage.unknown","uuid":"abc"}"#
    );
    assert_eq!(
        req("getActiveTokens", json!([]), json!(42)),
        r#"{"responseObject":[],"code":"200","uuid":"42"}"#
    );
    assert_eq!(
        req("getActiveTokens", json!([]), json!(true)),
        r#"{"responseObject":[],"code":"200","uuid":"true"}"#
    );
    for uuid in [json!(""), Value::Null] {
        assert_eq!(
            req("getActiveTokens", json!([]), uuid),
            r#"{"responseObject":[],"code":"200"}"#
        );
    }
    // A text reply is parsed again: org.json's order and escaping.
    assert_eq!(
        req("textJson", json!([]), json!("u")),
        r#"{"errorMessage":"<\/x>","errorCode":"NONE","uuid":"u"}"#
    );
    assert_eq!(
        req("nope", json!([]), json!("abc")),
        r#"{"code":"500","message":"NoSuchMethodException nope"}"#
    );
    assert_eq!(
        req("saveKey", json!(["a", "b"]), json!("abc")),
        "{\"code\":\"500\",\"message\":\"java.lang.IllegalAccessException: Class \
         kz.gov.pki.knca.NCALayerCommonActivator can not access a member of class \
         kz.gov.pki.knca.CommonUtils with modifiers \\\"private\\\". Method: saveKey\"}"
    );
}

#[test]
fn methods_are_found_by_name_and_argument_count() {
    let ctx = Ctx::default();
    for (name, args) in [
        ("getKeyInfo", json!([])),
        ("getKeyInfo", json!(["PKCS12", "x"])),
        ("getActiveTokens", json!(["x"])),
        ("toString", json!([])),
        ("GetKeyInfo", json!(["PKCS12"])),
        ("", json!([])),
    ] {
        assert_eq!(
            method(&ctx, name, args.clone()),
            error(&format!("NoSuchMethodException {name}")),
            "{name} {args}"
        );
    }
    assert!(ctx.calls.lock().unwrap().is_empty());
}

#[test]
fn request_errors_are_org_json_messages() {
    let ctx = Ctx::default();
    assert_eq!(
        call(&ctx, json!({"uuid": "u"})),
        error("JSONObject[\"method\"] not found.")
    );
    for name in [json!(5), Value::Null, json!(["getActiveTokens"])] {
        assert_eq!(
            call(&ctx, json!({"method": name})),
            error("JSONObject[\"method\"] is not a string.")
        );
    }
    assert_eq!(
        raw(&ctx, &CLASS, r#"{"method":"plain","method":"plain"}"#),
        error("Duplicate key \"method\" at 27 [character 28 line 1]")
    );
}

#[test]
fn private_and_unconvertible_methods_are_refused() {
    let ctx = Ctx::default();
    let private = |name: &str| {
        error(&format!(
            "java.lang.IllegalAccessException: Class kz.gov.pki.knca.NCALayerCommonActivator \
             can not access a member of class kz.gov.pki.knca.CommonUtils with modifiers \
             \"private\". Method: {name}"
        ))
    };
    for (name, args) in [
        ("saveKey", json!([{}, [1]])),
        ("getJson", json!([null])),
        ("getJson", json!([[1, "2", -3.5, "+4"]])),
    ] {
        assert_eq!(method(&ctx, name, args), private(name));
    }
    // `getJson(Object)` takes an `int[]`, which the dispatcher converts first.
    for (array, index) in [
        (json!(["x"]), 0),
        (json!([1, true]), 1),
        (json!([1, "2147483648"]), 1),
        (json!([null]), 0),
        (json!([[1]]), 0),
    ] {
        assert_eq!(
            method(&ctx, "getJson", json!([array])),
            error(&format!("JSONArray[{index}] is not a int."))
        );
    }
    // Other parameter types take an `Object[]`: no element conversion.
    assert_eq!(
        method(&ctx, "saveKey", json!([["x"], [true]])),
        private("saveKey")
    );
    for args in [json!(["x"]), json!([{}]), json!([[]]), json!([null])] {
        assert_eq!(
            method(&ctx, "setKeyInfoServices", args),
            error(
                "java.lang.IllegalArgumentException: argument type mismatch. Method: \
                 setKeyInfoServices"
            )
        );
    }
}

#[test]
fn arguments_must_have_the_parameter_types() {
    let ctx = Ctx::default();
    let mismatch = |name: &str| {
        error(&format!(
            "java.lang.IllegalArgumentException: argument type mismatch. Method: {name}"
        ))
    };
    for (name, args) in [
        ("getKeyInfo", json!([5])),
        ("getKeyInfo", json!([null])),
        ("getKeyInfo", json!([["PKCS12"]])),
        ("getKeyInfo", json!([{"a": 1}])),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", "YQ==", "true"]),
        ),
        ("createCAdESFromBase64", json!(["PKCS12", "", "YQ==", null])),
        ("signXmls", json!(["PKCS12", "", "<a/>", "", ""])),
        ("ints", json!([5])),
    ] {
        assert_eq!(
            method(&ctx, name, args.clone()),
            mismatch(name),
            "{name} {args}"
        );
    }
    // A `String[]` parameter takes only strings; the conversion fails before the call.
    assert_eq!(
        call(
            &ctx,
            json!({"method": "signXmls", "uuid": "u", "args": ["PKCS12", "", ["<a/>", 1], "", ""]})
        ),
        error("JSONArray[1] is not a String.")
    );
    assert!(ctx.calls.lock().unwrap().is_empty());
    // What fits is passed.
    method(
        &ctx,
        "signXmls",
        json!(["PKCS12", "", ["<a/>", "<b/>"], "", ""]),
    );
    method(
        &ctx,
        "createCAdESFromBase64",
        json!(["PKCS12", "", "YQ==", true]),
    );
    method(&ctx, "object", json!([null]));
    method(&ctx, "object", json!([[1, "2"]]));
    method(&ctx, "ints", json!([[3]]));
    assert_eq!(
        *ctx.calls.lock().unwrap(),
        [
            r#"signXmls ["<a/>", "<b/>"]"#.to_owned(),
            "createCAdES true".to_owned(),
            format!("object {:?}", Arg::Value(&Value::Null)),
            format!("object {:?}", Arg::Ints(vec![1, 2])),
            format!("ints {:?}", Arg::Ints(vec![3])),
        ]
    );
}

#[test]
fn thrown_is_an_invocation_target_exception() {
    let ctx = Ctx::default();
    assert_eq!(
        call(&ctx, json!({"method": "throws", "uuid": "u"})),
        error("java.lang.reflect.InvocationTargetException. Method: throws")
    );
}

#[test]
fn null_without_uuid_drops() {
    let ctx = Ctx::default();
    assert_eq!(
        raw(&ctx, &CLASS, r#"{"method":"changeLang","args":["kk"]}"#),
        Reply::Drop
    );
}

#[test]
fn null_with_uuid_is_500() {
    let ctx = Ctx::default();
    assert_eq!(
        call(
            &ctx,
            json!({"method": "changeLang", "args": ["kk"], "uuid": "u"})
        ),
        r#"{"code":"500"}"#
    );
}

#[test]
fn text_with_uuid_is_parse_error() {
    let ctx = Ctx::default();
    assert_eq!(
        call(&ctx, json!({"method": "plain", "uuid": "u"})),
        error("A JSONObject text must begin with '{' at 1 [character 2 line 1]")
    );
}

#[test]
fn nldoc_lang_hook_runs_before_invoke() {
    let ctx = Ctx::default();
    let nldoc = |request: Value| raw(&ctx, &NLDOC, &request.to_string());
    // The hook runs for a method found, before `Method.invoke` refuses it.
    nldoc(json!({"method": "saveKey", "args": ["a", "b"], "lang": "kk"}));
    assert_eq!(*ctx.lang.lock().unwrap(), "kk");
    // `changeLang` itself: the hook with the request's `lang`, then the argument.
    nldoc(json!({"method": "changeLang", "args": ["en"], "lang": "kk", "uuid": "u"}));
    assert_eq!(*ctx.lang.lock().unwrap(), "en");
    // Not for a conversion error.
    nldoc(json!({"method": "getJson", "args": [["x"]], "lang": "kk"}));
    assert_eq!(*ctx.lang.lock().unwrap(), "en");
}

#[test]
fn no_such_method_uses_previous_locale() {
    let ctx = Ctx::default();
    let nldoc = |request: Value| raw(&ctx, &NLDOC, &request.to_string()).into_text().unwrap();
    assert_eq!(
        nldoc(json!({"method": "nope", "lang": "kk"})),
        r#"{"code":"500","message":"В модуле нет такого метода nope"}"#
    );
    nldoc(json!({"method": "getActiveTokens", "lang": "kk"}));
    assert_eq!(
        nldoc(json!({"method": "nope", "lang": "ru"})),
        r#"{"code":"500","message":"Модульде мұндай әдіс жоқ nope"}"#
    );
}
