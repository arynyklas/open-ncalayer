//! MP8 (docs/design/manual-plugins.md 4.8): an error answer carries an optional `subcode`
//! string next to the stable `code`. Additive: an error without one is byte-for-byte what it
//! was, the `ErrorCode` set is unchanged, and a peer that sends garbage in the field loses
//! only the field, never the typed code.
use oncl_api::error::{ApiError, AppliedState, ErrorCode};
use serde_json::{Value, json};

#[test]
fn an_error_without_a_subcode_serializes_exactly_as_before() {
    let error = ApiError::not_applied(ErrorCode::PermissionDenied);
    assert_eq!(
        serde_json::to_string(&error).unwrap(),
        r#"{"code":"PermissionDenied","applied":"NotApplied"}"#
    );
    assert_eq!(error.subcode(), None);
}

#[test]
fn an_error_with_a_subcode_adds_one_field_after_applied() {
    let error = ApiError::not_applied(ErrorCode::PermissionDenied).with_subcode("not-granted");
    assert_eq!(
        serde_json::to_string(&error).unwrap(),
        r#"{"code":"PermissionDenied","applied":"NotApplied","subcode":"not-granted"}"#
    );
    assert_eq!(error.subcode(), Some("not-granted"));
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(error.applied, AppliedState::NotApplied);
}

#[test]
fn an_import_name_is_a_valid_subcode() {
    let error = ApiError::not_applied(ErrorCode::InteractionRequired).with_subcode("keys_select");
    assert_eq!(error.subcode(), Some("keys_select"));
}

#[test]
fn a_subcode_outside_the_pattern_is_dropped_not_carried() {
    for bad in [
        "",
        "1abc",
        "-abc",
        "a b",
        "a\nb",
        "a\u{1b}[31m",
        "naïve",
        "<script>",
        &"a".repeat(65),
    ] {
        let error = ApiError::not_applied(ErrorCode::PermissionDenied).with_subcode(bad);
        assert_eq!(error.subcode(), None, "{bad:?}");
        assert!(
            !serde_json::to_string(&error).unwrap().contains("subcode"),
            "{bad:?}"
        );
    }
    let longest = "a".repeat(64);
    let error = ApiError::not_applied(ErrorCode::PermissionDenied).with_subcode(longest.clone());
    assert_eq!(error.subcode(), Some(longest.as_str()));
}

#[test]
fn parsing_accepts_a_missing_and_a_present_subcode() {
    let plain: ApiError =
        serde_json::from_str(r#"{"code":"PermissionDenied","applied":"NotApplied"}"#).unwrap();
    assert_eq!(plain.subcode(), None);
    let typed: ApiError = serde_json::from_str(
        r#"{"code":"PermissionDenied","applied":"NotApplied","subcode":"options-mismatch"}"#,
    )
    .unwrap();
    assert_eq!(typed.subcode(), Some("options-mismatch"));
    let null: ApiError = serde_json::from_str(
        r#"{"code":"PermissionDenied","applied":"NotApplied","subcode":null}"#,
    )
    .unwrap();
    assert_eq!(null.subcode(), None);
}

#[test]
fn a_hostile_subcode_never_costs_the_typed_code_and_is_never_surfaced() {
    for hostile in [
        json!("evil\r\nforged: line"),
        json!("a".repeat(5000)),
        json!("x\u{202e}y"),
        json!(""),
    ] {
        let body = json!({"code":"PermissionDenied","applied":"Applied","subcode":hostile});
        let error: ApiError = serde_json::from_value(body).unwrap();
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(error.applied, AppliedState::Applied);
        assert_eq!(error.subcode(), None);
    }
}

#[test]
fn unknown_fields_and_a_non_string_subcode_are_ignored_not_fatal() {
    let error: ApiError = serde_json::from_str(
        r#"{"code":"PermissionDenied","applied":"NotApplied","extra":1,"subcode":7}"#,
    )
    .unwrap();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(error.subcode(), None);
}

#[test]
fn the_published_error_schema_has_an_optional_bounded_subcode() {
    let document = oncl_api::openapi::document();
    let schema = &document["components"]["schemas"]["ApiError"];
    let mut properties: Vec<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    properties.sort();
    assert_eq!(properties, ["applied", "code", "subcode"]);
    let mut required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    required.sort();
    assert_eq!(required, ["applied", "code"], "the subcode stays optional");
    let subcode = &schema["properties"]["subcode"];
    assert_eq!(subcode["type"], "string");
    assert_eq!(subcode["maxLength"], 64);
    assert_eq!(subcode["pattern"], "^[A-Za-z][A-Za-z0-9_-]{0,63}$");
    assert_eq!(schema["additionalProperties"], false);
    // The stable code contract is untouched.
    let codes = document["components"]["schemas"]["ErrorCode"]["enum"]
        .as_array()
        .unwrap();
    assert_eq!(codes.len(), 19, "no new ErrorCode: the subcode is a field");
}

#[test]
fn the_openapi_publishes_a_plugin_refusal_example_that_the_mirror_parses() {
    let document = oncl_api::openapi::document();
    let responses = &document["paths"]["/v1/operations"]["post"]["responses"];
    let examples = &responses["403"]["content"]["application/json"]["examples"];
    let refusal = &examples["plugin_refusal"]["value"];
    assert_eq!(refusal["code"], "PermissionDenied");
    assert_eq!(refusal["applied"], "NotApplied");
    assert!(refusal["subcode"].is_string(), "{refusal}");
    let parsed: ApiError = serde_json::from_value(refusal.clone()).unwrap();
    assert!(parsed.subcode().is_some());
    // A plain refusal stays a plain example without the field.
    let plain: &Value = &examples["plain"]["value"];
    assert!(plain.get("subcode").is_none(), "{plain}");
    // A failed terminal record can carry the subcode too.
    let failed = &responses["200"]["content"]["multipart/mixed"]["examples"]["failed_plugin_refusal"]
        ["value"];
    assert_eq!(failed["status"], "failed");
    assert!(failed["error"]["subcode"].is_string(), "{failed}");
}

// --- the client exposes the subcode on its error type -----------------------------------

#[cfg(feature = "client")]
mod client {
    use oncl_api::client::{
        ApiClient, ArtifactSink, ClientConfig, ExecuteOptions, FailureKind, Request, Route, Source,
    };
    use oncl_api::dto::{ItemMetadata, Operation, OperationMetadata, PartMetadata, PartRole};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    struct Discard;
    impl ArtifactSink for Discard {
        fn begin(&mut self, _: &str, _: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// One-shot server: reads the whole request, answers `status` with a JSON body.
    fn answer(status: &str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_owned();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buffer = [0u8; 4096];
            let (mut end, mut length) = (None, 0usize);
            loop {
                let n = stream.read(&mut buffer).unwrap_or(0);
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buffer[..n]);
                if end.is_none()
                    && let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    end = Some(at + 4);
                    let head = String::from_utf8_lossy(&seen[..at]).to_lowercase();
                    length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                }
                if end.is_some_and(|e| seen.len() >= e + length) {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        format!("http://{address}")
    }

    fn call(endpoint: &str) -> oncl_api::client::ClientError {
        let metadata = OperationMetadata {
            items: vec![ItemMetadata {
                id: "p".into(),
                operation: Operation::Extract { input: "d".into() },
            }],
            parts: vec![PartMetadata {
                name: "d".into(),
                item_id: "p".into(),
                role: PartRole::Document,
            }],
        };
        let request = Request::new(
            Route::Operations,
            &metadata,
            vec![("d".into(), Source::Memory(Zeroizing::new(b"abc".to_vec())))],
        )
        .unwrap();
        let client = ApiClient::new(
            endpoint,
            Zeroizing::new("token".to_owned()),
            ClientConfig::new().allow_plain_http(true),
        )
        .unwrap();
        let options = ExecuteOptions {
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(20),
            control: Arc::new(|| Ok(())),
        };
        client
            .execute(request, &mut Discard, &options)
            .expect_err("the service refused")
    }

    #[test]
    fn a_refusal_with_a_subcode_exposes_it_next_to_the_code() {
        let endpoint = answer(
            "403 Forbidden",
            r#"{"code":"PermissionDenied","applied":"NotApplied","subcode":"not-granted"}"#,
        );
        let error = call(&endpoint);
        assert_eq!(error.kind, FailureKind::Rejected);
        assert_eq!(
            error.server_code,
            Some(oncl_api::error::ErrorCode::PermissionDenied)
        );
        assert_eq!(error.server_subcode.as_deref(), Some("not-granted"));
        assert_eq!(error.code(), "PermissionDenied");
        assert_eq!(error.describe(), "PermissionDenied; subcode=not-granted");
        assert_eq!(
            error.to_string(),
            "PermissionDenied; subcode=not-granted; applied=NotApplied"
        );
    }

    #[test]
    fn a_refusal_without_a_subcode_is_unchanged() {
        let endpoint = answer(
            "403 Forbidden",
            r#"{"code":"PermissionDenied","applied":"NotApplied"}"#,
        );
        let error = call(&endpoint);
        assert_eq!(error.server_subcode, None);
        assert_eq!(error.describe(), "PermissionDenied");
        assert_eq!(error.to_string(), "PermissionDenied; applied=NotApplied");
    }

    #[test]
    fn a_hostile_subcode_is_never_printed() {
        let endpoint = answer(
            "403 Forbidden",
            r#"{"code":"PermissionDenied","applied":"NotApplied","subcode":"x\r\noncl: forged"}"#,
        );
        let error = call(&endpoint);
        assert_eq!(error.kind, FailureKind::Rejected);
        assert_eq!(error.server_subcode, None);
        assert_eq!(error.to_string(), "PermissionDenied; applied=NotApplied");
    }
}
