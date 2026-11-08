//! `kz.sapa.eproc.osgi.EprocModule`: `signXml` (root-keyed request; `storageName = PKCS12`,
//! `keyType = SIGNATURE`, `uid` and `chain` fixed by the template), the whole document or
//! one element with the signature in a parent.
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::PluginParam;
use oncl_plugin::operations::{KeyKind, Profile, Source};

const PORT: &str = "eproc";
const XML: &str = "<r><data Id=\"d1\">actual XML text</data><s></s></r>";
const MODULE: &str = "kz.sapa.eproc.osgi.EprocModule";

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    let all = [
        ("xml", PluginParam::Text(XML)),
        ("tbs", PluginParam::Text("/r/data")),
        ("parent", PluginParam::Text("/r/s")),
    ];
    let params = if operation == "sign-xml" {
        &all[..1]
    } else {
        &all[..]
    };
    run_port_operation(PORT, operation, params, options)
}

fn signed_of(run: &PortRun) -> String {
    let reply = reply_json(run);
    assert_eq!(reply["code"], "200", "{reply} {:?}", run.http_log);
    assert_eq!(reply["uid"], "manual");
    assert!(reply["newChain"].is_string(), "{reply}");
    reply["responseObject"].as_str().unwrap().to_owned()
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_signs_the_whole_document() {
    let run = run_operation("sign-xml", &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({
            "module": MODULE, "method": "signXml", "uid": "manual",
            "storageName": "PKCS12", "keyType": "SIGNATURE", "xml": XML
        }),
    );
    assert_eq!(run.summary.kind, KeyKind::Xml);
    assert_eq!(run.summary.profile, Profile::Xml(Default::default()));
    let signed = signed_of(&run);
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["r"], "{:?}", facts.json);
    oracle::assert_xml_rejected(signed.replace("actual", "forged!").as_bytes(), &run.cert);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_element_signs_the_element_into_the_parent() {
    let run = run_operation("sign-xml-element", &RunOptions::default());
    assert_applied(&run);
    assert_request(
        &run,
        serde_json::json!({
            "module": MODULE, "method": "signXml", "uid": "manual",
            "storageName": "PKCS12", "keyType": "SIGNATURE", "xml": XML,
            "tbsElementXPath": "/r/data", "signatureParentElementXPath": "/r/s"
        }),
    );
    let Profile::Xml(profile) = &run.summary.profile else {
        panic!("{:?}", run.summary.profile)
    };
    assert_eq!(profile.element, Some(Source::Fixed("/r/data".to_owned())));
    assert_eq!(profile.parent, Some(Source::Fixed("/r/s".to_owned())));
    let signed = signed_of(&run);
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["data"], "{:?}", facts.json);
    assert!(signed.contains("<s><ds:Signature"), "{signed}");
    assert_eq!(without_signature(&signed), XML);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_field_is_refused_before_the_key() {
    // The `xml` profile has the element and the parent only: the whole-document operation
    // is tampered into an element one, the element operation into another element.
    let tampers = [
        (
            "sign-xml",
            "content = \"param:xml\"",
            "content = \"param:xml\"\n\n[operations.uses.key.profile]\nelement = \"/r/data\"",
        ),
        (
            "sign-xml-element",
            "element = \"param:tbs\"",
            "element = \"/r/s\"",
        ),
        (
            "sign-xml-element",
            "parent = \"param:parent\"",
            "parent = \"/r\"",
        ),
    ]
    .map(|(o, f, t)| (o.to_owned(), f.to_owned(), t.to_owned()));
    assert_tampers_refused(&tampers, &run_operation);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    let operations = ["sign-xml".to_owned(), "sign-xml-element".to_owned()];
    assert_every_import_needed(PORT, &operations, &["keys_release"], &run_operation);
}

/// A failure after the key was chosen (the element is its own parent): the key is dropped,
/// which calls `keys_release` (declared), and the call ends with the port's own 500 reply,
/// not an opaque `Denied`.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_failure_after_the_key_is_the_ports_error_reply() {
    let params = [
        ("xml", PluginParam::Text(XML)),
        ("tbs", PluginParam::Text("/r/s")),
        ("parent", PluginParam::Text("/r/s")),
    ];
    let run = run_port_operation(PORT, "sign-xml-element", &params, &RunOptions::default());
    assert!(run.call.error().is_none(), "{:?}", run.call);
    let reply = reply_json(&run);
    assert_eq!(reply["code"], "500", "{reply}");
    assert_eq!(reply["uid"], "manual");
    assert!(
        reply["message"]
            .as_str()
            .is_some_and(|m| m.contains("родительским")),
        "{reply}"
    );
    assert_eq!(run.applications, 0);
}

/// `keys_release` is called only when the key is dropped without being kept (a failure after
/// the choice): without the import that failure ends as an opaque `Denied`.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn keys_release_is_needed_on_the_failure_path() {
    let params = [
        ("xml", PluginParam::Text(XML)),
        ("tbs", PluginParam::Text("/r/s")),
        ("parent", PluginParam::Text("/r/s")),
    ];
    let tamper =
        |text: &str| text.replace("\"keys_select\", \"keys_release\", ", "\"keys_select\", ");
    let options = RunOptions {
        tamper: Some(Box::new(tamper)),
        ..RunOptions::default()
    };
    let run = run_port_operation(PORT, "sign-xml-element", &params, &options);
    assert!(
        matches!(run.call.error(), Some(e) if e.code() == oncl_core::ErrorCode::PermissionDenied),
        "{:?}",
        run.call
    );
    assert!(run.call.response().is_none());
}
