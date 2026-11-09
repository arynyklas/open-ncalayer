//! `EFactoringSign`: `text` (a CMS of the typed text, four variants: attached or detached, with or
//! without Kalkan's time-stamp), `xml` (the whole document) and `xml` with `sign_element` and
//! `signature_parent_element` (`sign-xml-element`: the two XPaths are typed parameters).
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::{PluginParam, PluginPrepareError, TicketRefusal};
use oncl_pdk::abi;
use oncl_plugin::operations::{KeyKind, Profile, Source};

const PORT: &str = "efactoring";
const TEXT: &str =
    "Договор №1: текст, который подтвердил пользователь\nвторая строка\tс табуляцией";
const XML: &str = "<r><data Id=\"d1\">actual XML text</data></r>";
const ELEMENT_XML: &str = "<r><data Id=\"d1\">actual XML text</data><s></s></r>";

fn text_operation(suffix: &str) -> String {
    format!("sign-text-{suffix}")
}

fn run_element(element: &str, parent: &str, options: &RunOptions) -> PortRun {
    run_port_operation(
        PORT,
        "sign-xml-element",
        &[
            ("xml", PluginParam::Text(ELEMENT_XML)),
            ("element", PluginParam::Text(element)),
            ("parent", PluginParam::Text(parent)),
        ],
        options,
    )
}

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    if operation == "sign-xml" {
        run_port_operation(PORT, operation, &[("xml", PluginParam::Text(XML))], options)
    } else if operation == "sign-xml-element" {
        run_element("/r/data", "/r/s", options)
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
    all.push("sign-xml-element".to_owned());
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
    // The element form: every field of its profile that the module's call fixes.
    for (from, to) in [
        ("c14n = \"exclusive\"", "c14n = \"inclusive\""),
        (
            "{ c14n = \"inclusive_with_comments\" }",
            "{ c14n = \"exclusive_with_comments\" }",
        ),
        ("[\"enveloped\", ", "["),
        (
            "\ntransforms = [\"enveloped\", { c14n = \"inclusive_with_comments\" }]",
            "",
        ),
        ("strip_whitespace = true", "strip_whitespace = false"),
        ("base64_line_breaks = false", "base64_line_breaks = true"),
        ("trim = true", "trim = false"),
        ("prefix = \"SOAP-ENV\"", "prefix = \"SOAP\""),
        (
            "other_prefix_uri = \"http://www.w3.org/2000/09/xmldsig#\"",
            "other_prefix_uri = \"http://www.w3.org/2000/09/xmldsig\"",
        ),
        ("element = \"param:element\"", "element = \"/r/other\""),
        ("parent = \"param:parent\"", "parent = \"/r\""),
    ] {
        tampers.push((
            "sign-xml-element".to_owned(),
            from.to_owned(),
            to.to_owned(),
        ));
    }
    assert_tampers_refused(&tampers, &run_operation);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    assert_every_import_needed(PORT, &operations(), &[], &run_operation);
}

const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// `xml` with `sign_element` and `signature_parent_element`: the module asks for
/// `transforms = [Enveloped, C14N-with-comments]`; the declaration says so, the two XPaths are
/// the user's typed text, and the signature verifies independently.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_element_signs_the_element_under_the_parent() {
    let run = run_element("/r/data", "/r/s", &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({
            "module": "EFactoringSign", "type": "xml", "data": ELEMENT_XML,
            "sign_element": "/r/data", "signature_parent_element": "/r/s"
        }),
    );
    assert_eq!(run.summary.kind, KeyKind::XmlEx);
    let Profile::XmlEx(profile) = &run.summary.profile else {
        panic!("{:?}", run.summary.profile)
    };
    assert_eq!(profile.element, Some(Source::Fixed("/r/data".to_owned())));
    assert_eq!(profile.parent, Some(Source::Fixed("/r/s".to_owned())));
    assert_eq!(
        profile.transforms,
        Some(vec![
            abi::Transform::Enveloped,
            abi::Transform::C14n(abi::C14n::InclusiveWithComments)
        ])
    );
    let reply = reply_json(&run);
    assert_eq!(reply["errorCode"], "NONE", "{reply} {:?}", run.http_log);
    let signed = reply["result"].as_str().unwrap();
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["data"], "{:?}", facts.json);
    let signature = &facts.json["signatures"][0];
    assert_eq!(signature["c14n"], EXC_C14N);
    assert_eq!(
        signature["references"][0]["transforms"],
        serde_json::json!([ENVELOPED, C14N_COMMENTS])
    );
    assert!(signed.contains("<s><ds:Signature"), "{signed}");
    assert_eq!(
        without_signature(signed),
        ELEMENT_XML,
        "the document is as it was"
    );
    assert!(!signed.starts_with("<?xml"), "no declaration");
    oracle::assert_xml_rejected(signed.replace("actual", "forged!").as_bytes(), &run.cert);
}

/// The module fails when the parent is the element itself (ignoring case): in the module, before
/// the key is used. Its retry window is a dialog, which no operation declares, so the dialog is
/// denied and the call ends as `Denied` (the module's `CANCEL` reply is not reached): no
/// signature, no key use.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_parent_that_is_the_element_fails_in_the_module_before_the_key() {
    for parent in ["/r/data", "/R/DATA"] {
        let run = run_element("/r/data", parent, &RunOptions::default());
        assert_eq!(run.applications, 0, "{parent}: no key use");
        assert_eq!(run.call.applied(), AppliedState::NotApplied, "{parent}");
        assert!(run.call.refusals().is_empty(), "{parent}: {:?}", run.call);
        assert!(run.call.response().is_none(), "{parent}: {:?}", run.call);
        assert!(
            matches!(run.call.error(), Some(e) if e.code() == oncl_core::ErrorCode::PermissionDenied),
            "{parent}: {:?}",
            run.call
        );
    }
}

/// An empty parent or element is no XPath: the host refuses the call before the module runs
/// (a typed XPath must be absolute), so the port's own rule for an empty parent is never met.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn an_empty_or_relative_xpath_is_refused_by_the_host() {
    for (element, parent) in [
        ("/r/data", ""),
        ("", "/r/s"),
        ("/r/data", "s"),
        ("data", "/r/s"),
    ] {
        let error = try_run_port_operation(
            PORT,
            "sign-xml-element",
            &[
                ("xml", PluginParam::Text(ELEMENT_XML)),
                ("element", PluginParam::Text(element)),
                ("parent", PluginParam::Text(parent)),
            ],
            &RunOptions::default(),
        );
        assert!(
            matches!(error, Err(PluginPrepareError::Options)),
            "{element:?} {parent:?}: {:?}",
            error.map(|r| r.call)
        );
    }
}

/// The whole-document operation does not cover the element form: the module sends the profile of
/// the request it got (here the element form's), and `sign-xml` does not say it.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_whole_document_operation_does_not_cover_the_element_form() {
    let options = RunOptions {
        tamper: Some(Box::new(|text| {
            text.replacen(
                "{\"module\":\"EFactoringSign\",\"type\":\"xml\",\"data\":\"{xml}\"}",
                "{\"module\":\"EFactoringSign\",\"type\":\"xml\",\"data\":\"{xml}\",\"sign_element\":\"/r/data\",\"signature_parent_element\":\"/r\"}",
                1,
            )
        })),
        ..RunOptions::default()
    };
    let run = run_port_operation(
        PORT,
        "sign-xml",
        &[("xml", PluginParam::Text(XML))],
        &options,
    );
    assert_refused_before_the_key(&run);
    assert_eq!(
        run.call.refusals(),
        [TicketRefusal::Options],
        "{:?}",
        run.call
    );
}
