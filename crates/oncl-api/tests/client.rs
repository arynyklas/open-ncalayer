//! The client's contract with the service DTOs: the owned response mirror must parse every
//! response the real DTOs serialize (the published OpenAPI examples are produced by them),
//! and the endpoint policy is a pure function of the address.
use oncl_api::client::{Endpoint, FailureKind, FinalRecord};
use oncl_api::dto::{ItemMetadata, Operation, OperationMetadata, PartMetadata, PartRole};

fn examples(path: &str, content: &[&str]) -> Vec<(String, serde_json::Value)> {
    let document = oncl_api::openapi::document();
    let mut found = Vec::new();
    for media in content {
        let examples =
            &document["paths"][path]["post"]["responses"]["200"]["content"][media]["examples"];
        for (name, example) in examples.as_object().into_iter().flatten() {
            found.push((format!("{path} {media} {name}"), example["value"].clone()));
        }
    }
    found
}

#[test]
fn the_owned_response_mirror_parses_every_published_service_response() {
    let mut all = examples("/v1/operations", &["application/json", "multipart/mixed"]);
    all.extend(examples("/v1/batch", &["multipart/mixed"]));
    assert!(all.len() >= 8, "the published examples disappeared");
    for (name, value) in all {
        // Failed records carry no `results`' artifacts; every example is a terminal record.
        let record: FinalRecord = serde_json::from_value(value.clone())
            .unwrap_or_else(|error| panic!("{name}: {error}: {value}"));
        let _ = record.operation_id();
        let _ = record.artifact_ids();
    }
}

#[test]
fn request_metadata_built_by_the_client_is_what_the_service_accepts() {
    let metadata = OperationMetadata {
        items: vec![ItemMetadata {
            id: "op".into(),
            operation: Operation::Extract { input: "d1".into() },
        }],
        parts: vec![PartMetadata {
            name: "d1".into(),
            item_id: "op".into(),
            role: PartRole::Document,
        }],
    };
    let wire = serde_json::to_string(&metadata).unwrap();
    assert_eq!(
        wire,
        r#"{"items":[{"id":"op","operation":{"kind":"extract","input":"d1"}}],"parts":[{"name":"d1","item_id":"op","role":"document"}]}"#
    );
    // `deny_unknown_fields` of the service DTO accepts exactly what the client wrote.
    let back: OperationMetadata = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.items.len(), 1);
}

#[test]
fn plain_http_is_loopback_only_unless_explicitly_allowed_and_nothing_else_is_an_endpoint() {
    for ok in [
        "http://127.0.0.1:13579",
        "http://127.1.2.3",
        "http://[::1]:9",
        "http://localhost:80/",
        "https://signing.internal:443",
        "https://203.0.113.9",
    ] {
        Endpoint::parse(ok, false).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for (bad, kind) in [
        ("http://203.0.113.9:13579", FailureKind::PlainHttpRefused),
        ("http://signing.internal", FailureKind::PlainHttpRefused),
        ("ftp://127.0.0.1", FailureKind::InvalidEndpoint),
        ("127.0.0.1:13579", FailureKind::InvalidEndpoint),
        ("http://user:pw@127.0.0.1", FailureKind::InvalidEndpoint),
        ("http://127.0.0.1/path", FailureKind::InvalidEndpoint),
        ("http://127.0.0.1?x=1", FailureKind::InvalidEndpoint),
        ("http://127.0.0.1:0", FailureKind::InvalidEndpoint),
        ("http://", FailureKind::InvalidEndpoint),
        ("https://exa mple.test", FailureKind::InvalidEndpoint),
    ] {
        assert_eq!(Endpoint::parse(bad, false).unwrap_err().kind, kind, "{bad}");
    }
    // The documented allowance (a protected backend network) is the only way past it.
    let allowed = Endpoint::parse("http://203.0.113.9:13579", true).unwrap();
    assert!(!allowed.is_tls() && !allowed.is_loopback());
}
