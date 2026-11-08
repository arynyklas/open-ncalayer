//! `EFactoringSign`: `text` (a CMS of the typed text, four variants: attached or detached, with or
//! without Kalkan's time-stamp) and `xml` (the whole document).
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::PluginParam;
use oncl_plugin::operations::{KeyKind, Profile};

const PORT: &str = "efactoring";
const TEXT: &str =
    "Договор №1: текст, который подтвердил пользователь\nвторая строка\tс табуляцией";
const XML: &str = "<r><data Id=\"d1\">actual XML text</data></r>";

fn text_operation(suffix: &str) -> String {
    format!("sign-text-{suffix}")
}

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    if operation == "sign-xml" {
        run_port_operation(PORT, operation, &[("xml", PluginParam::Text(XML))], options)
    } else {
        run_port_operation(
            PORT,
            operation,
            &[("text", PluginParam::Text(TEXT))],
            options,
        )
    }
}

fn text_run(suffix: &str, attached: bool, timestamped: bool) {
    let run = run_operation(&text_operation(suffix), &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({
            "module": "EFactoringSign",
            "type": "text",
            "data": TEXT,
            "attach": attached,
            "has_timestamp": timestamped
        }),
    );
    let reply = reply_json(&run);
    assert_eq!(reply["errorCode"], "NONE", "{reply} {:?}", run.http_log);
    let cms = from_base64(reply["result"].as_str().unwrap());
    // The signed bytes are the UTF-8 bytes of the typed text.
    assert_cms(&run, &cms, TEXT.as_bytes(), attached, timestamped);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_text_attached_with_a_time_stamp() {
    text_run("attached-timestamp", true, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_text_attached() {
    text_run("attached", true, false);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_text_detached_with_a_time_stamp() {
    text_run("detached-timestamp", false, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_text_detached() {
    text_run("detached", false, false);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_signs_the_whole_document() {
    let run = run_operation("sign-xml", &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({"module": "EFactoringSign", "type": "xml", "data": XML}),
    );
    assert_eq!(run.summary.kind, KeyKind::XmlEx);
    assert!(matches!(run.summary.profile, Profile::XmlEx(_)));
    let reply = reply_json(&run);
    assert_eq!(reply["errorCode"], "NONE", "{reply} {:?}", run.http_log);
    let signed = reply["result"].as_str().unwrap();
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["r"], "{:?}", facts.json);
    assert_eq!(without_signature(signed), XML, "the document is as it was");
    assert!(!signed.starts_with("<?xml"), "no declaration");
    oracle::assert_xml_rejected(signed.replace("actual", "forged!").as_bytes(), &run.cert);
}

fn operations() -> Vec<String> {
    let mut all: Vec<String> = CMS_VARIANTS
        .iter()
        .map(|(s, ..)| text_operation(s))
        .collect();
    all.push("sign-xml".to_owned());
    all
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_field_is_refused_before_the_key() {
    let mut tampers: Vec<_> = CMS_VARIANTS
        .iter()
        .map(|(s, a, t)| cms_tamper(&text_operation(s), "content = \"param:text\"", *a, *t))
        .collect();
    for (from, to) in [
        ("strip_whitespace = true", "strip_whitespace = false"),
        ("base64_line_breaks = false", "base64_line_breaks = true"),
        ("trim = true", "trim = false"),
        (
            "placement = \"document_element\"",
            "placement = \"first_child_of_document\"",
        ),
    ] {
        tampers.push(("sign-xml".to_owned(), from.to_owned(), to.to_owned()));
    }
    assert_tampers_refused(&tampers, &run_operation);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    assert_every_import_needed(PORT, &operations(), &[], &run_operation);
}

const PROBE: &str = r#"
[[operations]]
name = "probe-element"
module = "EFactoringSign"
manual = true
request = '{"module":"EFactoringSign","type":"xml","data":"{xml}","sign_element":"/r/data","signature_parent_element":"/r/s"}'
label = { ru = "а", kk = "ә", en = "a" }

[[operations.params]]
name = "xml"
kind = "text"
max_chars = 1000

[operations.uses]
imports = ["keys_choose", "keys_release", "random", "keys_sign_xml_ex"]
network = "pki"

[[operations.uses.key]]
kind = "xml_ex"
content = "param:xml"

[operations.uses.key.profile]
element = "/r/data"
parent = "/r/s"
placement = "parent"
namespaces = [{ prefix = "SOAP-ENV", uri = "http://schemas.xmlsoap.org/soap/envelope/" }]
other_prefix_uri = "http://www.w3.org/2000/09/xmldsig#"
c14n = "exclusive"
strip_whitespace = true
base64_line_breaks = false
output = { serialize = { declaration = false, standalone_no = false, trim = true } }
"#;

/// `xml` with `sign_element`: the module passes `transforms = [Enveloped, C14N-with-comments]`,
/// which no profile can say: NOT declared; Core refuses the call before the key.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_element_form_of_xml_cannot_be_declared() {
    let run = probe(
        PORT,
        "probe-element",
        PROBE,
        &[(
            "xml",
            PluginParam::Text("<r><data Id=\"d1\">x</data><s/></r>"),
        )],
    );
    assert_denied_for_transforms(&run);
}
