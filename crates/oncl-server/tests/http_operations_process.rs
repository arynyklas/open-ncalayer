#[path = "server_support/mod.rs"]
mod support;

#[test]
fn standalone_binary_dispatches_typed_json_to_the_real_sdk() {
    let process = support::Process::start("");
    let runtime = support::runtime();
    let (status, bytes) = runtime.block_on(support::request(
        process.address,
        &process.token,
        "/v1/operations",
        br#"{"metadata":{"items":[{"id":"process","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"process","role":"document"}]},"documents":{"doc":"abc"}}"#,
        &[("content-type", "application/json")],
        None,
    ));
    assert_eq!(status, 200);
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["type"], "final");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["results"][0]["item_id"], "process");
    assert_eq!(result["results"][0]["applied"], "NotApplied");
    assert_eq!(result["results"][0]["result"]["bytes_in"], 3);
    assert_eq!(
        result["results"][0]["result"]["digest"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    process.stop();
}
