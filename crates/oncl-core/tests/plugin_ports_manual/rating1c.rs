//! `kz.rating1c.edo.signUtils`: `signXml`, `createCmsFromBase64`, `createRawSignFromBase64`.
use crate::ports::*;
use oncl_core::plugins::{PluginParam, TicketRefusal};
use oncl_plugin::operations::{KeyKind, Profile};

const PORT: &str = "rating1c";
const DOC: &[u8] = b"1C-Rating EDO: the document the user approved";
const XML: &str = "<r><data Id=\"d1\">actual XML text</data><s></s></r>";

const IGNORE: &str = "needs the built port wasm: see docs/dev/plugins-manual-tests.md";

fn response_object(run: &PortRun) -> serde_json::Value {
    let json = reply_json(run);
    assert_eq!(json["code"], "200", "{json} {:?}", run.http_log);
    json["responseObject"].clone()
}

/// `signed` without its `ds:Signature` element.
fn without_signature(signed: &str) -> String {
    let start = signed.find("<ds:Signature").expect("a ds:Signature");
    let end = signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    format!("{}{}", &signed[..start], &signed[end..])
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_signs_the_whole_document() {
    let _ = IGNORE;
    let params = [("xml", PluginParam::Text(XML))];
    let run = run_port_operation(PORT, "sign-xml", &params, &RunOptions::default());
    assert_applied(&run);
    // The request is exactly the one a WSS page sends for this method.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&run.request).unwrap(),
        serde_json::json!({
            "module": "kz.rating1c.edo.signUtils",
            "method": "signXml",
            "args": ["PKCS12", "SIGNATURE", XML, "", "", ""]
        })
    );
    assert_eq!(run.summary.kind, KeyKind::XmlEx);
    assert!(matches!(run.summary.profile, Profile::XmlEx(_)));
    assert_eq!(run.summary.content.len, XML.len() as u64);
    let signed = response_object(&run);
    let signed = signed.as_str().unwrap();
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["r"], "{:?}", facts.json);
    assert_eq!(without_signature(signed), XML, "the document is as it was");
    assert!(!signed.starts_with("<?xml"), "no declaration");
    // The oracle can say no.
    oracle::assert_xml_rejected(signed.replace("actual", "forged!").as_bytes(), &run.cert);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_element_signs_the_element_into_the_parent() {
    let params = [
        ("xml", PluginParam::Text(XML)),
        ("tbs", PluginParam::Text("/r/data")),
        ("parent", PluginParam::Text("/r/s")),
    ];
    let run = run_port_operation(PORT, "sign-xml-element", &params, &RunOptions::default());
    assert_applied(&run);
    // The XPaths the user typed are in the profile the summary shows.
    let Profile::XmlEx(profile) = &run.summary.profile else {
        panic!("{:?}", run.summary.profile)
    };
    use oncl_plugin::operations::Source;
    assert_eq!(profile.element, Some(Source::Fixed("/r/data".to_owned())));
    assert_eq!(profile.parent, Some(Source::Fixed("/r/s".to_owned())));
    let signed = response_object(&run);
    let signed = signed.as_str().unwrap();
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["data"], "{:?}", facts.json);
    // The signature is the child of `s`, not of the document element.
    assert!(signed.contains("<s><ds:Signature"), "{signed}");
    assert_eq!(without_signature(signed), XML);
}

fn cms_run(operation: &str, attached: bool, timestamped: bool) {
    let params = [("file", PluginParam::Document(DOC))];
    let run = run_port_operation(PORT, operation, &params, &RunOptions::default());
    assert_applied(&run);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&run.request).unwrap(),
        serde_json::json!({
            "module": "kz.rating1c.edo.signUtils",
            "method": "createCmsFromBase64",
            "args": ["PKCS12", "SIGNATURE", base64_of(DOC), attached, timestamped, ""]
        })
    );
    assert_eq!(run.summary.kind, KeyKind::CmsEx);
    assert_eq!(run.summary.content.len, DOC.len() as u64);
    let cms = from_base64(response_object(&run).as_str().unwrap());
    let facts = oracle::verify_cms(&cms, DOC, &run.cert, attached);
    assert_eq!(facts.sig_alg, oncl_pki::key::SigAlg::RsaSha256);
    assert_eq!(facts.time_stamped, timestamped, "{facts:?}");
    // Kalkan's TSA binding is a GET; the signer's own OCSP check precedes it.
    let tsa = run
        .http_log
        .iter()
        .any(|l| l.starts_with("GET http://tsp.pki.gov.kz/"));
    assert_eq!(tsa, timestamped, "{:?}", run.http_log);
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn create_cms_detached() {
    cms_run("create-cms", false, false);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn create_cms_attached() {
    cms_run("create-cms-attached", true, false);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn create_cms_detached_with_a_time_stamp() {
    cms_run("create-cms-timestamp", false, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn create_cms_attached_with_a_time_stamp() {
    cms_run("create-cms-attached-timestamp", true, true);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn create_raw_sign_is_a_valid_rsa_signature_over_the_document() {
    let params = [("file", PluginParam::Document(DOC))];
    let run = run_port_operation(PORT, "create-raw-sign", &params, &RunOptions::default());
    assert_applied(&run);
    assert_eq!(run.summary.kind, KeyKind::Raw);
    assert_eq!(run.summary.profile, Profile::Raw);
    let object = response_object(&run);
    let signature = from_base64(object["signResult"].as_str().unwrap());
    oracle::verify_raw_rsa(&run.cert, DOC, &signature);
    assert!(object["signerCert"].is_string(), "{object}");
}

const OPERATIONS: [&str; 7] = [
    "sign-xml",
    "sign-xml-element",
    "create-cms",
    "create-cms-attached",
    "create-cms-timestamp",
    "create-cms-attached-timestamp",
    "create-raw-sign",
];

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    let xml = [
        ("xml", PluginParam::Text(XML)),
        ("tbs", PluginParam::Text("/r/data")),
        ("parent", PluginParam::Text("/r/s")),
    ];
    let doc = [("file", PluginParam::Document(DOC))];
    let params: &[(&str, PluginParam<'_>)] = match operation {
        "sign-xml" => &xml[..1],
        "sign-xml-element" => &xml[..],
        _ => &doc[..],
    };
    run_port_operation(PORT, operation, params, options)
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_field_is_refused_before_the_key() {
    // Each tampered declaration says something other than what the module passes to the
    // key import: Core's ticket compares, and nothing is signed. `create-raw-sign` has no
    // options to tamper (a raw profile has no fields).
    let with_profile = "content = \"param:file\"";
    let tampers: [(&'static str, &'static str, &'static str); 6] = [
        (
            "sign-xml",
            "strip_whitespace = true",
            "strip_whitespace = false",
        ),
        (
            "sign-xml-element",
            "base64_line_breaks = false",
            "base64_line_breaks = true",
        ),
        (
            "create-cms",
            with_profile,
            "content = \"param:file\"\n\n[operations.uses.key.profile]\nencapsulate = true",
        ),
        (
            "create-cms-attached",
            "encapsulate = true",
            "encapsulate = false",
        ),
        (
            "create-cms-timestamp",
            "timestamp = \"kalkan\"",
            "timestamp = \"basics\"",
        ),
        (
            "create-cms-attached-timestamp",
            "timestamp = \"kalkan\"",
            "timestamp = \"none\"",
        ),
    ];
    for (operation, from, to) in tampers {
        let run = run_operation(operation, &RunOptions::tampered(operation, from, to));
        assert_refused_before_the_key(&run);
        assert_eq!(run.call.refusals(), [TicketRefusal::Options], "{operation}");
        assert_eq!(
            run.call.subcode(),
            Some(oncl_core::plugins::PluginRefusalCode::OptionsMismatch),
            "{operation}"
        );
    }
}

/// Every import an operation declares is needed: with any one deleted the manifest is refused
/// or the call does not succeed (`Denied`, even after the key use for `keys_release`).
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    let manifest = oncl_plugin::Manifest::from_toml(&manifest_text(PORT)).unwrap();
    for operation in OPERATIONS {
        let op = manifest
            .operations()
            .iter()
            .find(|o| o.name() == operation)
            .unwrap();
        for import in op.uses().imports() {
            let name = import.name();
            let tamper = move |text: &str| {
                let start = text.find(&format!("name = \"{operation}\"\n")).unwrap();
                let end = text[start..]
                    .find("\n[[operations]]")
                    .map_or(text.len(), |n| start + n);
                let at = start + text[start..end].find("imports = [").unwrap();
                let line_end = at + text[at..].find('\n').unwrap();
                let line = &text[at..line_end];
                let new = line
                    .replace(&format!(", \"{name}\""), "")
                    .replace(&format!("\"{name}\", "), "");
                assert_ne!(new, line, "{operation}: {name}");
                format!("{}{}{}", &text[..at], new, &text[line_end..])
            };
            let options = RunOptions {
                tamper: Some(Box::new(tamper)),
                ..RunOptions::default()
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_operation(operation, &options)
            }));
            if let Ok(run) = outcome {
                assert!(
                    run.call.error().is_some() || run.call.applied() != AppliedState::Applied,
                    "{operation} works without {name}"
                );
            }
        }
    }
}

/// The oracle refuses what a signature wrapping would need: an unknown transform, a second
/// element with the signed Id placed before the signed one, a signature without references.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_xml_oracle_rejects_wrapping_shapes() {
    let params = [
        ("xml", PluginParam::Text(XML)),
        ("tbs", PluginParam::Text("/r/data")),
        ("parent", PluginParam::Text("/r/s")),
    ];
    let run = run_port_operation(PORT, "sign-xml-element", &params, &RunOptions::default());
    assert_applied(&run);
    let signed = response_object(&run).as_str().unwrap().to_owned();
    let c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    assert!(signed.contains(c14n), "{signed}");
    let unknown = signed.replacen(c14n, "urn:unknown-transform", 1);
    oracle::assert_xml_rejected_for(unknown.as_bytes(), &run.cert, "");
    let duplicate = signed.replacen(
        "<data Id=\"d1\">",
        "<data Id=\"d1\">x</data><data Id=\"d1\">",
        1,
    );
    oracle::assert_xml_rejected_for(duplicate.as_bytes(), &run.cert, "ambiguous");
    let start = signed.find("<ds:Reference").unwrap();
    let end = signed.find("</ds:Reference>").unwrap() + "</ds:Reference>".len();
    let none = format!("{}{}", &signed[..start], &signed[end..]);
    oracle::assert_xml_rejected_for(none.as_bytes(), &run.cert, "no references");
}
