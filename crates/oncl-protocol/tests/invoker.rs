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
    for bad in [r#""3""#, "1", "2.5", "null", "true", "[]"] {
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
