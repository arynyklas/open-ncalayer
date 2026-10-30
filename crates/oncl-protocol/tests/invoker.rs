use oncl_protocol::AddInfo;
use oncl_protocol::invoker::{CallResult, Failure, NlClass, invoke};
use serde_json::{Map, Value, json};

/// First class: the default for an empty `class`, like `PKIExtras`.
struct Extras;

impl NlClass for Extras {
    fn class_name(&self) -> &'static str {
        "PKIExtras"
    }

    fn call(
        &self,
        method: &str,
        args: Option<&Map<String, Value>>,
        add_info: &AddInfo,
    ) -> Option<CallResult> {
        Some(match method {
            "ok" => Ok(json!({"result": 1})),
            "cancel" => Ok(json!({})),
            "custom" => Err(Failure::Custom {
                code: "SIGNING_FAILURE".into(),
                message: Some("Signing failure.".into()),
                details: None,
            }),
            "customBare" => Err(Failure::Custom {
                code: "SIGNING_FAILURE".into(),
                message: None,
                details: None,
            }),
            "customFull" => Err(Failure::Custom {
                code: "SIGNING_FAILURE".into(),
                message: Some("Signing failure.".into()),
                details: Some("cause".into()),
            }),
            "throw" => Err(Failure::Invocation(Some(
                r#"org.json.JSONException: JSONObject["format"] not found."#.into(),
            ))),
            "throwBare" => Err(Failure::Invocation(None)),
            "general" => Err(Failure::General(None)),
            "echo" => Ok(json!({
                "args": args.cloned().map(Value::Object),
                "origin": add_info.origin,
            })),
            _ => return None,
        })
    }
}

/// Second class: reachable only by name, like `PKIEssentials`.
struct Essentials;

impl NlClass for Essentials {
    fn class_name(&self) -> &'static str {
        "PKIEssentials"
    }

    fn call(
        &self,
        method: &str,
        _: Option<&Map<String, Value>>,
        _: &AddInfo,
    ) -> Option<CallResult> {
        (method == "generateCsr").then(|| Ok(json!({"result": "csr"})))
    }
}

fn run(request: &str) -> String {
    run_with(request, &AddInfo::default())
}

fn run_with(request: &str, add_info: &AddInfo) -> String {
    invoke(request, add_info, &[&Extras, &Essentials])
}

fn parse(reply: &str) -> Value {
    serde_json::from_str(reply).expect("reply is JSON")
}

fn code(reply: String) -> String {
    parse(&reply)["code"]
        .as_str()
        .expect("reply has a code")
        .to_owned()
}

fn assert_json_eq(reply: String, expected: Value) {
    assert_eq!(parse(&reply), expected, "reply: {reply}");
}

const GENERAL: &str = r#"{"status":false,"code":"GENERAL_ERROR","message":"General error."}"#;

#[test]
fn invoke_success_and_cancel_shape() {
    assert_eq!(
        run(r#"{"method":"ok","args":{}}"#),
        r#"{"status":true,"body":{"result":1}}"#
    );
    assert_eq!(
        run(r#"{"method":"cancel","args":{}}"#),
        r#"{"status":true,"body":{}}"#
    );
}

#[test]
fn invoke_errors() {
    assert_json_eq(
        run(r#"{"method":"m","apiVersion":3}"#),
        json!({"status":false,"code":"GENERAL_ERROR","message":"General error.","details":"Supported apiVersion is 2"}),
    );
    assert_eq!(code(run(r#"{"method":"nope"}"#)), "GENERAL_ERROR");
    assert_eq!(
        code(run(
            r#"{"class":"PKIEssentials","method":"sign","args":{}}"#
        )),
        "GENERAL_ERROR"
    );
    assert!(!run(r#"{"method":"custom","args":{}}"#).contains("null"));
}

#[test]
fn error_field_order_is_exact() {
    assert_eq!(
        run(r#"{"method":"m","apiVersion":3}"#),
        r#"{"status":false,"code":"GENERAL_ERROR","message":"General error.","details":"Supported apiVersion is 2"}"#
    );
    assert_eq!(
        run(r#"{"method":"customFull"}"#),
        r#"{"status":false,"code":"SIGNING_FAILURE","message":"Signing failure.","details":"cause"}"#
    );
}

/// `CommonInvoker` reads `obj.optInt("apiVersion", 2)`: null and non-numbers default to 2,
/// numbers and numeric strings truncate toward zero.
#[test]
fn api_version() {
    assert_eq!(
        run(r#"{"method":"ok","apiVersion":2}"#),
        r#"{"status":true,"body":{"result":1}}"#
    );
    assert_eq!(
        run(r#"{"method":"ok"}"#),
        r#"{"status":true,"body":{"result":1}}"#
    );
    for good in [
        "null",
        r#""2""#,
        "2.0",
        "2.9",
        r#""2.9""#,
        r#""abc""#,
        r#"" 2""#,
        r#""02""#,
        r#""""#,
        "true",
        "[]",
        "{}",
        "4294967298",
    ] {
        assert_eq!(
            run(&format!(r#"{{"method":"ok","apiVersion":{good}}}"#)),
            r#"{"status":true,"body":{"result":1}}"#,
            "apiVersion {good}"
        );
    }
    for bad in ["1", "3", r#""3""#, "-0.5", "1.99", "3.1", r#""1e1""#, "-2"] {
        let reply = run(&format!(r#"{{"method":"ok","apiVersion":{bad}}}"#));
        assert_json_eq(
            reply,
            json!({"status":false,"code":"GENERAL_ERROR","message":"General error.","details":"Supported apiVersion is 2"}),
        );
    }
}

#[test]
fn invalid_request_is_general_error() {
    for request in [
        "",
        "nope",
        "[1]",
        "null",
        r#"{"args":{}}"#,
        r#"{"method":5}"#,
        r#"{"method":"ok""#,
    ] {
        assert_eq!(run(request), GENERAL, "request: {request}");
    }
}

#[test]
fn class_selection() {
    // Empty or absent `class` selects the first class.
    assert_eq!(
        run(r#"{"class":"","method":"ok"}"#),
        r#"{"status":true,"body":{"result":1}}"#
    );
    // A method of the second class is not reachable without naming it.
    assert_json_eq(
        run(r#"{"method":"generateCsr","args":{}}"#),
        json!({"status":false,"code":"GENERAL_ERROR","message":"General error.","details":"generateCsr is not defined in PKIExtras"}),
    );
    assert_eq!(
        run(r#"{"class":"PKIEssentials","method":"generateCsr","args":{}}"#),
        r#"{"status":true,"body":{"result":"csr"}}"#
    );
    assert_json_eq(
        run(r#"{"class":"PKIEssentials","method":"sign","args":{}}"#),
        json!({"status":false,"code":"GENERAL_ERROR","message":"General error.","details":"sign is not defined in PKIEssentials"}),
    );
    assert_eq!(run(r#"{"class":"PKIUnknown","method":"ok"}"#), GENERAL);
    assert_eq!(run(r#"{"class":7,"method":"ok"}"#), GENERAL);
}

#[test]
fn not_defined_details() {
    assert_eq!(
        run(r#"{"method":"nope"}"#),
        r#"{"status":false,"code":"GENERAL_ERROR","message":"General error.","details":"nope is not defined in PKIExtras"}"#
    );
}

#[test]
fn failure_shapes() {
    assert_eq!(
        run(r#"{"method":"custom"}"#),
        r#"{"status":false,"code":"SIGNING_FAILURE","message":"Signing failure."}"#
    );
    assert_eq!(
        run(r#"{"method":"customBare"}"#),
        r#"{"status":false,"code":"SIGNING_FAILURE"}"#
    );
    assert_eq!(
        run(r#"{"method":"throw"}"#),
        r#"{"status":false,"code":"INVOCATION_ERROR","message":"An invoked method threw an exception.","details":"org.json.JSONException: JSONObject[\"format\"] not found."}"#
    );
    assert_eq!(
        run(r#"{"method":"throwBare"}"#),
        r#"{"status":false,"code":"INVOCATION_ERROR","message":"An invoked method threw an exception."}"#
    );
    assert_eq!(run(r#"{"method":"general"}"#), GENERAL);
}

#[test]
fn args_and_add_info_reach_the_method() {
    let add_info = AddInfo {
        origin: Some("https://example.kz".into()),
        ..AddInfo::default()
    };
    assert_json_eq(
        run_with(r#"{"method":"echo","args":{"a":[1,"x"]}}"#, &add_info),
        json!({"status":true,"body":{"args":{"a":[1,"x"]},"origin":"https://example.kz"}}),
    );
    // Absent or non-object `args` reaches the method as `None`.
    assert_json_eq(
        run(r#"{"method":"echo"}"#),
        json!({"status":true,"body":{"args":null,"origin":null}}),
    );
    assert_json_eq(
        run(r#"{"method":"echo","args":[1]}"#),
        json!({"status":true,"body":{"args":null,"origin":null}}),
    );
}

#[test]
fn uuid_is_not_echoed() {
    assert_eq!(
        run(r#"{"module":"kz.gov.pki.knca.basics","uuid":"abc","method":"ok","args":{}}"#),
        r#"{"status":true,"body":{"result":1}}"#
    );
}

/// The original's `CommonInvoker` to the byte: `invoker::java`.
mod java {
    use oncl_protocol::invoker::Failure;
    use oncl_protocol::invoker::java::{
        BadRequest, CallResult, InvokeOptions, NlClass, NlMethod, invoke_with,
    };
    use oncl_protocol::orgjson::JValue;
    use oncl_protocol::{AddInfo, Reply};
    use serde_json::{Map, Value, json};

    struct Signer;

    const METHODS: &[NlMethod] = &[
        NlMethod {
            name: "getVersion",
            annotation: None,
            params: 0,
        },
        NlMethod {
            name: "signText",
            annotation: Some("sign"),
            params: 1,
        },
        NlMethod {
            name: "nothing",
            annotation: None,
            params: 0,
        },
        NlMethod {
            name: "fail",
            annotation: None,
            params: 0,
        },
        NlMethod {
            name: "withOrigin",
            annotation: None,
            params: 2,
        },
    ];

    impl NlClass for Signer {
        fn class_name(&self) -> &'static str {
            "SignerV2"
        }

        fn methods(&self) -> &'static [NlMethod] {
            METHODS
        }

        fn call(
            &self,
            method: &NlMethod,
            args: Option<&Map<String, Value>>,
            add_info: &AddInfo,
        ) -> CallResult {
            match method.name {
                "getVersion" => {
                    assert!(args.is_none(), "a method without parameters gets no args");
                    Ok(JValue::from("2.0.0"))
                }
                "signText" => Ok(JValue::from(Value::Object(args.unwrap().clone()))),
                "nothing" => Ok(JValue::Null),
                "fail" => Err(Failure::Invocation(Some(
                    r#"org.json.JSONException: JSONObject["xml"] not found."#.to_owned(),
                ))),
                "withOrigin" => Ok(JValue::from(add_info.origin.clone().unwrap_or_default())),
                _ => unreachable!(),
            }
        }
    }

    struct Other;

    impl NlClass for Other {
        fn class_name(&self) -> &'static str {
            "Other"
        }

        fn methods(&self) -> &'static [NlMethod] {
            &[]
        }

        fn call(&self, _: &NlMethod, _: Option<&Map<String, Value>>, _: &AddInfo) -> CallResult {
            unreachable!()
        }
    }

    fn invoke_as(bad_request: BadRequest, request: &str) -> Reply {
        let add_info = AddInfo {
            origin: Some("https://a.kz".to_owned()),
            session: 0,
        };
        invoke_with(
            request,
            &add_info,
            &[&Signer, &Other],
            &InvokeOptions { bad_request },
        )
    }

    fn invoke(request: Value) -> String {
        invoke_as(BadRequest::Drop, &request.to_string())
            .into_text()
            .unwrap()
    }

    fn general(details: &str) -> String {
        format!(
            r#"{{"code":"GENERAL_ERROR","details":"{details}","message":"General error.","status":false}}"#
        )
    }

    #[test]
    fn success_order_is_body_status() {
        assert_eq!(
            invoke(json!({"method": "getVersion"})),
            r#"{"body":"2.0.0","status":true}"#
        );
        // By the annotation's name too; the body object in `HashMap` order.
        assert_eq!(
            invoke(json!({"method": "sign", "args": {"errorCode": 1, "errorMessage": "</x>"}})),
            r#"{"body":{"errorMessage":"<\/x>","errorCode":1},"status":true}"#
        );
        assert_eq!(
            invoke(json!({"method": "withOrigin", "args": {}})),
            r#"{"body":"https://a.kz","status":true}"#
        );
    }

    #[test]
    fn null_body_is_omitted() {
        assert_eq!(invoke(json!({"method": "nothing"})), r#"{"status":true}"#);
    }

    #[test]
    fn failure_order_is_code_details_message_status() {
        assert_eq!(
            invoke(json!({"method": "fail"})),
            r#"{"code":"INVOCATION_ERROR","details":"org.json.JSONException: JSONObject[\"xml\"] not found.","message":"An invoked method threw an exception.","status":false}"#
        );
    }

    #[test]
    fn api_version_details_have_java_prefix() {
        assert_eq!(
            invoke(json!({"apiVersion": 3, "method": "getVersion"})),
            general("java.lang.IllegalArgumentException: Supported apiVersion is 2")
        );
        // `optInt`: a numeric string counts, anything else is the default.
        assert_eq!(
            invoke(json!({"apiVersion": "2", "method": "getVersion"})),
            r#"{"body":"2.0.0","status":true}"#
        );
        assert_eq!(
            invoke(json!({"apiVersion": true, "method": "getVersion"})),
            r#"{"body":"2.0.0","status":true}"#
        );
    }

    #[test]
    fn unknown_class_details() {
        assert_eq!(
            invoke(json!({"class": "Nope", "method": "getVersion"})),
            general("java.lang.IllegalArgumentException: Nope is not found")
        );
        // An empty or null class is the first; another class by its name.
        for class in [json!(""), Value::Null] {
            assert_eq!(
                invoke(json!({"class": class, "method": "getVersion"})),
                r#"{"body":"2.0.0","status":true}"#
            );
        }
        assert_eq!(
            invoke(json!({"class": "Other", "method": "getVersion"})),
            general("java.lang.IllegalArgumentException: getVersion is not defined in Other")
        );
    }

    #[test]
    fn non_string_class_is_stringified() {
        assert_eq!(
            invoke(json!({"class": 7, "method": "getVersion"})),
            general("java.lang.IllegalArgumentException: 7 is not found")
        );
        assert_eq!(
            invoke_as(BadRequest::Drop, r#"{"class":1.50,"method":"getVersion"}"#),
            general("java.lang.IllegalArgumentException: 1.50 is not found")
        );
    }

    #[test]
    fn demands_arguments_from_arity() {
        for args in [None, Some(json!([1])), Some(json!("x")), Some(Value::Null)] {
            let mut request = json!({"method": "signText"});
            if let Some(args) = args {
                request["args"] = args;
            }
            assert_eq!(
                invoke(request),
                general("java.lang.IllegalArgumentException: signText demands arguments")
            );
        }
    }

    #[test]
    fn zero_param_ignores_args() {
        assert_eq!(
            invoke(json!({"method": "getVersion", "args": {"a": 1}})),
            r#"{"body":"2.0.0","status":true}"#
        );
    }

    #[test]
    fn empty_method_is_not_defined() {
        assert_eq!(
            invoke(json!({"method": ""})),
            general("java.lang.IllegalArgumentException:  is not defined in SignerV2")
        );
        assert_eq!(
            invoke(json!({"method": "nope"})),
            general("java.lang.IllegalArgumentException: nope is not defined in SignerV2")
        );
    }

    #[test]
    fn bad_request_drop() {
        for request in [
            "[1]",
            r#"{"class":"SignerV2"}"#,
            r#"{"method":5}"#,
            r#"{"method":"getVersion","method":"getVersion"}"#,
        ] {
            assert_eq!(
                invoke_as(BadRequest::Drop, request),
                Reply::Drop,
                "{request}"
            );
        }
        // Built-in modules' way: a reply without details.
        assert_eq!(
            invoke_as(BadRequest::Reply, r#"{"class":"SignerV2"}"#),
            r#"{"code":"GENERAL_ERROR","message":"General error.","status":false}"#
        );
    }

    #[test]
    fn bad_request_catch_all_has_org_json_details() {
        assert_eq!(
            invoke_as(BadRequest::CatchAll, r#"{"class":"SignerV2"}"#),
            general(r#"org.json.JSONException: JSONObject[\"method\"] not found."#)
        );
        assert_eq!(
            invoke_as(BadRequest::CatchAll, r#"{"method":true}"#),
            general(r#"org.json.JSONException: JSONObject[\"method\"] is not a string."#)
        );
        assert_eq!(
            invoke_as(BadRequest::CatchAll, r#"{"method":"a","method":"b"}"#),
            general(
                r#"org.json.JSONException: Duplicate key \"method\" at 23 [character 24 line 1]"#
            )
        );
    }
}
