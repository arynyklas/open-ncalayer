//! `kz.fhs.cabinet.FHSCabinetSigner` V1: `signXml` (`args` is a JSON object), `signText`
//! (detached CMS with a Kalkan time-stamp).
//!
//! On failure the module opens a `dialog_choice` error window; the manual window has no
//! dialogs, so the plugin's retry window is not available (recorded in the labels). The key
//! chooser is Core's own; the harness key is the module's PKCS12 storage.
use crate::ports::*;
use crate::wave3_kit::base64_of;
use oncl_core::plugins::{PluginParam, TicketRefusal};
use oncl_plugin::operations::{KeyKind, Profile};

const PORT: &str = "fhs";
const DOC: &[u8] = b"FHS cabinet: the data the user approved";
const XML: &str = "<r><data>actual XML text</data></r>";

fn run_operation(operation: &str, options: &RunOptions) -> PortRun {
    let xml = [("xml", PluginParam::Text(XML))];
    let doc = [("file", PluginParam::Document(DOC))];
    let params: &[(&str, PluginParam<'_>)] = if operation == "sign-xml" { &xml } else { &doc };
    run_port_operation(PORT, operation, params, options)
}

fn message(run: &PortRun) -> String {
    let json = reply_json(run)["body"].clone();
    assert_eq!(json["code"], "200", "{json} {:?}", run.http_log);
    json["message"].as_str().expect("a message").to_owned()
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_xml_signs_the_document_with_the_args_object() {
    let run = run_operation("sign-xml", &RunOptions::default());
    assert_applied(&run);
    // The request is the one the cabinet page sends: `args` is an OBJECT.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&run.request).unwrap(),
        serde_json::json!({
            "module": "kz.fhs.cabinet.FHSCabinetSigner",
            "method": "signXml",
            "args": { "xml": XML }
        })
    );
    assert_eq!(run.summary.kind, KeyKind::Xml);
    assert!(matches!(run.summary.profile, Profile::Xml(_)));
    assert_eq!(run.summary.content.len, XML.len() as u64);
    let signed = message(&run);
    let facts = oracle::verify_xml(signed.as_bytes(), &run.cert, 1);
    assert_eq!(facts.referenced_nodes(), ["r"], "{:?}", facts.json);
    oracle::assert_xml_rejected(signed.replace("actual", "forged!").as_bytes(), &run.cert);
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_text_is_a_detached_time_stamped_cms_of_the_data() {
    let run = run_operation("sign-text", &RunOptions::default());
    assert_applied(&run);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&run.request).unwrap(),
        serde_json::json!({
            "module": "kz.fhs.cabinet.FHSCabinetSigner",
            "method": "signText",
            "args": { "base64data": base64_of(DOC) }
        })
    );
    assert_eq!(run.summary.kind, KeyKind::CmsEx);
    assert_eq!(run.summary.content.len, DOC.len() as u64);
    let cms = from_base64(&message(&run));
    let facts = oracle::verify_cms(&cms, DOC, &run.cert, false);
    assert_eq!(facts.sig_alg, oncl_pki::key::SigAlg::RsaSha256);
    assert!(facts.time_stamped, "{facts:?}");
    assert!(
        run.http_log
            .iter()
            .any(|l| l.starts_with("GET http://tsp.pki.gov.kz/")),
        "{:?}",
        run.http_log
    );
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn a_wrong_profile_is_refused_before_the_key() {
    let tampers: [(&'static str, &'static str, &'static str); 2] = [
        (
            "sign-xml",
            "content = \"param:xml\"",
            "content = \"param:xml\"\n\n[operations.uses.key.profile]\nelement = \"/r/data\"",
        ),
        (
            "sign-text",
            "timestamp = \"kalkan\"",
            "timestamp = \"basics\"",
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

/// With any declared import deleted the manifest is refused or the call does not succeed.
#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    let manifest = oncl_plugin::Manifest::from_toml(&manifest_text(PORT)).unwrap();
    for operation in ["sign-xml", "sign-text"] {
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
